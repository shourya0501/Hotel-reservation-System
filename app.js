/* ==========================================================================
   app.js : checkout controller (vanilla JavaScript, no framework)

   Flow
     Step 1  Stay details: live availability from GET /api/rooms/search
     Step 2  Guest details: validates the primary guest and contact information
     Step 3  Payment details: validates the card and POSTs /api/bookings for a hold
     Step 4  Review: countdown, then POST /api/payments captures the card
     Step 5  Receipt

   Design notes
     - One state object. Every user action updates it, then render functions redraw.
     - Card details live only in memory (cardDraft) and are cleared after payment.
     - Money is handled as integer paise in the subtotal, so no floating-point drift.
     - Stale search replies are ignored, so an older response cannot overwrite a newer one.
   ========================================================================== */

'use strict';

// ============================================================ Constants
const API = '/api';
const TOKEN_KEY = 'hotel.token';     // sessionStorage: cleared when the tab closes
const USER_KEY = 'hotel.user';
const LIVE_REFRESH_MS = 60 * 1000;
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;   // same pattern as server.cpp
const PHONE_RE = /^\+?[0-9]{10,15}$/;                                   // same pattern as server.cpp
const PAYMENT_FIELDS = ['contactEmail', 'contactPhone', 'cardNumber', 'cardExpiry', 'cardCvv'];
const inr = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' });

// ============================================================ State
const state = {
  step: 1,               // 1 stay, 2 guest details, 3 payment details, 4 review, 5 receipt
  user: null,            // { customer_id, full_name, email }
  guest: null,           // validated primary guest details
  search: null,          // last successful /api/rooms/search response
  travel: null,          // { check_in, check_out, guests } behind that search
  selectedTypeId: null,  // room_type_id chosen in step 1
  booking: null,         // hold returned by POST /api/bookings
  contact: null,         // { email, phone } used for the current hold
  holdExpiresAt: 0,      // epoch milliseconds when the hold ends
  receipt: null          // result of POST /api/payments, plus booking details
};

let token = null;         // bearer token for authenticated requests
let cardDraft = null;     // { number, expiry, cvv, last4 }: memory only, never persisted
let searchSeq = 0;        // identifies the most recent search request
let editTimer = null;     // debounce for travel edits
let holdInterval = null;  // countdown ticker
let liveInterval = null;  // availability refresh ticker
let authMode = 'login';
let pendingAction = null; // function to run after a successful sign-in

// ============================================================ Helpers
const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const plural = (n, word) => (n === 1 ? word : `${word}s`);

const toPaise = (value) => Math.round(Number(value) * 100);     // "5000.00" -> 500000
const formatPaise = (paise) => inr.format(paise / 100);
const formatMoney = (value) => formatPaise(toPaise(value));     // server money string in, text out

function isoDate(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function addDays(iso, days) {
  // Local midnight avoids the one-day shift that UTC parsing can cause.
  const date = new Date(`${iso}T00:00:00`);
  date.setDate(date.getDate() + days);
  return isoDate(date);
}

function nightsBetween(checkIn, checkOut) {
  return Math.round((new Date(checkOut) - new Date(checkIn)) / 86400000);
}

function formatDate(iso) {
  return new Date(`${iso}T00:00:00`).toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric'
  });
}

function luhnValid(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = Number(digits[i]);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function isFutureExpiry(value) {
  const match = /^(0[1-9]|1[0-2])\/(\d{2})$/.exec(value);
  if (!match) return false;
  const month = Number(match[1]);
  const year = 2000 + Number(match[2]);
  const now = new Date();
  return year > now.getFullYear() || (year === now.getFullYear() && month >= now.getMonth() + 1);
}

// ============================================================ API client
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, { method = 'GET', body, auth = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth) {
    if (!token) throw new ApiError(401, 'Please sign in to continue.');
    headers.Authorization = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetch(API + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  } catch (networkError) {
    throw new ApiError(0, 'Cannot reach the server. Check your connection and try again.');
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && auth) clearSession();   // token expired or invalid
    throw new ApiError(response.status, data.error || `Request failed with status ${response.status}.`);
  }
  return data;
}

// ============================================================ Session
function restoreSession() {
  token = sessionStorage.getItem(TOKEN_KEY);
  try {
    state.user = token ? JSON.parse(sessionStorage.getItem(USER_KEY)) : null;
  } catch (_) {
    state.user = null;
    token = null;
  }
}

function setSession(newToken, user) {
  token = newToken;
  state.user = user;
  sessionStorage.setItem(TOKEN_KEY, newToken);
  sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  renderAccount();
}

function clearSession() {
  token = null;
  state.user = null;
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
  renderAccount();
}

function renderAccount() {
  const signedIn = Boolean(token && state.user);
  $('signInBtn').hidden = signedIn;
  $('signOutBtn').hidden = !signedIn;
  $('accountName').hidden = !signedIn;
  $('accountName').textContent = signedIn ? `Hi, ${state.user.full_name.split(' ')[0]}` : '';
}

// ============================================================ Shared UI helpers
function showAlert(message, type = 'error') {
  const box = $('alert');
  box.textContent = message;
  box.className = `alert alert-${type}`;
  box.hidden = !message;
}

function setLiveStatus(text) {
  $('liveStatus').textContent = text;
}

function renderRows(container, rows) {
  container.replaceChildren();
  rows.forEach(([label, value, className]) => {
    const row = el('div', className);
    row.append(el('dt', '', label), el('dd', '', value));
    container.append(row);
  });
}

function renderStepper() {
  document.querySelectorAll('.stepper li').forEach((item) => {
    const n = Number(item.dataset.step);
    const current = n === state.step;
    const done = state.step === 5 || n < state.step;
    item.classList.toggle('active', current);
    item.classList.toggle('done', done);
    if (current) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
  });
}

function goToStep(step) {
  const changed = step !== state.step;
  state.step = step;
  document.querySelectorAll('[data-panel]').forEach((panel) => {
    panel.hidden = Number(panel.dataset.panel) !== step;
  });
  renderStepper();
  showAlert('');
  if (step === 2) prefillContact();
  if (changed) $('checkoutTitle').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Runs a task while disabling double-clicks. The button keeps its layout and only changes its label.
async function withBusy(button, label, task) {
  if (button.dataset.busy === 'true') return;
  button.dataset.busy = 'true';
  const original = button.textContent;
  button.textContent = label;
  try {
    await task();
  } finally {
    button.textContent = original;
    delete button.dataset.busy;
  }
}

// Sends a 401 back through sign-in, so the guest can resume the same action.
function reportError(err, retry) {
  if (err.status === 401 && retry) {
    openAuth(retry, 'Your session has ended. Please sign in again to continue.');
  } else {
    showAlert(err.message);
  }
}

// ============================================================ Step 1: travel and availability
function setupDates() {
  const today = isoDate(new Date());
  $('checkIn').min = today;
  $('checkIn').value = addDays(today, 1);
  $('checkOut').value = addDays(today, 2);
  syncDateLimits();
}

function syncDateLimits() {
  const checkIn = $('checkIn').value;
  if (checkIn) $('checkOut').min = addDays(checkIn, 1);
}

function readTravel() {
  return {
    check_in: $('checkIn').value,
    check_out: $('checkOut').value,
    guests: Number($('guests').value)
  };
}

function travelProblem(t) {
  if (!t.check_in || !t.check_out) return 'Choose a check-in and a check-out date.';
  if (t.check_in < isoDate(new Date())) return 'Check-in cannot be in the past.';
  if (t.check_out <= t.check_in) return 'Check-out must be after check-in.';
  if (nightsBetween(t.check_in, t.check_out) > 30) return 'The maximum stay is 30 nights.';
  if (!Number.isInteger(t.guests) || t.guests < 1 || t.guests > 10) {
    return 'Guests must be between 1 and 10.';
  }
  return '';
}

async function searchRooms({ silent = false } = {}) {
  const travel = readTravel();
  const problem = travelProblem(travel);
  if (problem) {
    if (!silent) showAlert(problem);
    return false;
  }

  const seq = ++searchSeq;
  setLiveStatus('Checking live availability…');
  try {
    const data = await api(`/rooms/search?${new URLSearchParams(travel)}`);
    if (seq !== searchSeq) return false;   // a newer search has already started

    state.search = data;
    state.travel = travel;
    $('hotelName').textContent = data.hotel;

    if (state.selectedTypeId && !data.rooms.some((r) => r.room_type_id === state.selectedTypeId)) {
      state.selectedTypeId = null;
      showAlert('Your selected room is no longer free for these dates. Please choose another.', 'warning');
    }

    const time = new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
    setLiveStatus(`Live availability, updated ${time}`);
    renderRooms();
    renderSidebar();
    return true;
  } catch (err) {
    if (seq !== searchSeq) return false;
    if (silent) setLiveStatus(`Could not refresh availability: ${err.message}`);
    else showAlert(err.message);
    return false;
  }
}

function roomCard(room) {
  const card = el('label', 'room-card');
  card.dataset.typeId = String(room.room_type_id);

  const radio = el('input', 'sr-only');
  radio.type = 'radio';
  radio.name = 'roomType';
  radio.value = String(room.room_type_id);
  radio.checked = room.room_type_id === state.selectedTypeId;

  const info = el('div');
  info.append(
    el('h3', '', room.name),
    el('p', 'muted', `Up to ${room.max_occupancy} guests · ${room.available_rooms} ${plural(room.available_rooms, 'room')} left`)
  );

  const price = el('div', 'room-price');
  price.append(
    el('strong', '', `${formatMoney(room.nightly_rate)} / night`),
    el('span', '', `Stay total ${formatMoney(room.estimate.total)}`)
  );

  card.append(radio, info, price);
  return card;
}

function renderRooms() {
  const list = $('roomList');
  list.replaceChildren();
  if (!state.search) return;

  if (state.search.rooms.length === 0) {
    list.append(el('p', 'empty', 'No rooms are free for these dates. Try other dates or fewer guests.'));
  } else {
    state.search.rooms.forEach((room) => list.append(roomCard(room)));
  }
  updateRoomSelection();
}

function updateRoomSelection() {
  document.querySelectorAll('.room-card').forEach((card) => {
    card.classList.toggle('selected', Number(card.dataset.typeId) === state.selectedTypeId);
  });
  $('toStep2').disabled = !state.selectedTypeId;
}

function selectedRoom() {
  if (!state.search || !state.selectedTypeId) return null;
  return state.search.rooms.find((r) => r.room_type_id === state.selectedTypeId) || null;
}

function onRoomPicked(typeId) {
  if (state.selectedTypeId === typeId) return;
  state.selectedTypeId = typeId;
  releaseHold();          // a different room needs a different hold
  updateRoomSelection();
  renderSidebar();
}

function onTravelEdited() {
  syncDateLimits();
  releaseHold();          // the current hold no longer matches the dates
  clearTimeout(editTimer);
  editTimer = setTimeout(() => searchRooms(), 350);
}

async function continueToPayment() {
  await withBusy($('toStep2'), 'Checking…', async () => {
    const travel = readTravel();
    const problem = travelProblem(travel);
    if (problem) {
      showAlert(problem);
      return;
    }

    const unchanged = state.travel && state.search &&
      state.travel.check_in === travel.check_in &&
      state.travel.check_out === travel.check_out &&
      state.travel.guests === travel.guests;
    if (!unchanged && !(await searchRooms())) return;

    if (!selectedRoom()) {
      showAlert('Choose a room type to continue.');
      return;
    }
    goToStep(2);
  });
}

// ============================================================ Step 2: payment details
function prefillContact() {
  if (state.guest) {
    if (!$('contactEmail').value) $('contactEmail').value = state.guest.email;
    if (!$('contactPhone').value) $('contactPhone').value = state.guest.phone;
  } else if (state.user && !$('contactEmail').value) {
    $('contactEmail').value = state.user.email;
  }
}

const COUNTRY_OPTIONS = [
  ['IN', 'India'], ['US', 'United States'], ['GB', 'United Kingdom'], ['CA', 'Canada'],
  ['AU', 'Australia'], ['NZ', 'New Zealand'], ['AE', 'United Arab Emirates'],
  ['SG', 'Singapore'], ['MY', 'Malaysia'], ['TH', 'Thailand'], ['JP', 'Japan'],
  ['CN', 'China'], ['FR', 'France'], ['DE', 'Germany'], ['ES', 'Spain'],
  ['IT', 'Italy'], ['NL', 'Netherlands'], ['RU', 'Russia'], ['ZA', 'South Africa'],
  ['BR', 'Brazil'], ['LK', 'Sri Lanka'], ['NP', 'Nepal'], ['BD', 'Bangladesh'],
  ['PK', 'Pakistan'], ['OTHER', 'Other']
];

function fillCountrySelect(select) {
  select.replaceChildren(new Option('Select', ''));
  COUNTRY_OPTIONS.forEach(([code, name]) => select.add(new Option(name, code)));
}

function updateGuestIdTypes() {
  const select = $('guestIdType');
  const nationality = $('guestNationality').value;
  select.replaceChildren(new Option('Select', ''));
  const types = nationality === 'IN'
    ? [['aadhaar', 'Aadhaar'], ['passport', 'Passport'], ['driving_licence', 'Driving licence'], ['voter_id', 'Voter ID']]
    : [['passport', 'Passport']];
  types.forEach(([value, label]) => select.add(new Option(label, value)));
}

function setupGuestSelects() {
  fillCountrySelect($('guestNationality'));
  fillCountrySelect($('guestResidence'));
  updateGuestIdTypes();
  $('guestNationality').addEventListener('change', updateGuestIdTypes);
}

function validateGuestForm() {
  const guest = {
    full_name: $('guestFullName').value.trim(),
    dob: $('guestDob').value,
    gender: $('guestGender').value,
    nationality: $('guestNationality').value,
    residence: $('guestResidence').value,
    id_type: $('guestIdType').value,
    id_number: $('guestIdNumber').value.trim(),
    email: $('contactEmail').value.trim(),
    phone: $('contactPhone').value.replace(/[\s-]/g, ''),
    purpose: $('guestPurpose').value
  };
  const errors = {};
  if (guest.full_name.length < 2) errors.guestFullName = 'Enter the guest’s full name.';
  if (!guest.dob || !isAdult(guest.dob)) errors.guestDob = 'The primary guest must be at least 18.';
  if (!guest.gender) errors.guestGender = 'Select a gender option.';
  if (!guest.nationality) errors.guestNationality = 'Select a nationality.';
  if (!guest.residence) errors.guestResidence = 'Select a country of residence.';
  if (!guest.id_type) errors.guestIdType = 'Select an ID type.';
  if (guest.id_number.length < 3) errors.guestIdNumber = 'Enter a valid ID or passport number.';
  if (!EMAIL_RE.test(guest.email)) errors.contactEmail = 'Enter a valid email address.';
  if (!PHONE_RE.test(guest.phone)) errors.contactPhone = 'Enter 10 to 15 digits, with an optional + prefix.';
  if (!guest.purpose) errors.guestPurpose = 'Select the purpose of your stay.';

  Object.entries(errors).forEach(([id, message]) => {
    $(id).setAttribute('aria-invalid', 'true');
    document.querySelector(`[data-error-for="${id}"]`).textContent = message;
  });
  ['guestFullName', 'guestDob', 'guestGender', 'guestNationality', 'guestResidence', 'guestIdType', 'guestIdNumber', 'contactEmail', 'contactPhone', 'guestPurpose']
    .filter((id) => !errors[id])
    .forEach((id) => {
      $(id).removeAttribute('aria-invalid');
      const error = document.querySelector(`[data-error-for="${id}"]`);
      if (error) error.textContent = '';
    });

  return { guest, errors };
}

function isAdult(iso) {
  const dob = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(dob.getTime())) return false;
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const beforeBirthday = today.getMonth() < dob.getMonth() ||
    (today.getMonth() === dob.getMonth() && today.getDate() < dob.getDate());
  if (beforeBirthday) age -= 1;
  return age >= 18;
}

function clearGuestForm() {
  state.guest = null;
  $('guestForm').reset();
  $('guestForm').querySelectorAll('[aria-invalid="true"]').forEach((field) => field.removeAttribute('aria-invalid'));
  $('guestForm').querySelectorAll('.field-error').forEach((error) => { error.textContent = ''; });
  updateGuestIdTypes();
}

function submitGuestForm(event) {
  event.preventDefault();
  const { guest, errors } = validateGuestForm();
  const firstError = Object.keys(errors)[0];
  if (firstError) {
    $(firstError).focus();
    showAlert('Please complete the highlighted guest details.');
    return;
  }
  state.guest = guest;
  // Normalize the phone once so validation, booking, and the summary use the same value.
  $('contactPhone').value = guest.phone;
  goToStep(3);
}

function readPaymentForm() {
  const values = {
    email: $('contactEmail').value.trim(),
    phone: $('contactPhone').value.replace(/[\s-]/g, ''),
    number: $('cardNumber').value.replace(/\D/g, ''),
    expiry: $('cardExpiry').value.trim(),
    cvv: $('cardCvv').value.trim()
  };

  const errors = {};
  if (!EMAIL_RE.test(values.email)) errors.contactEmail = 'Enter a valid email address.';
  if (!PHONE_RE.test(values.phone)) errors.contactPhone = 'Enter 10 to 15 digits, with an optional + prefix.';
  if (!/^\d{13,19}$/.test(values.number) || !luhnValid(values.number)) {
    errors.cardNumber = 'Enter a valid card number.';
  }
  if (!isFutureExpiry(values.expiry)) errors.cardExpiry = 'Enter a future expiry date as MM/YY.';
  if (!/^\d{3,4}$/.test(values.cvv)) errors.cardCvv = 'CVV must be 3 or 4 digits.';

  return { errors, values };
}

function showFieldErrors(errors) {
  PAYMENT_FIELDS.forEach((id) => {
    const message = errors[id] || '';
    $(id).setAttribute('aria-invalid', String(Boolean(message)));
    document.querySelector(`[data-error-for="${id}"]`).textContent = message;
  });
}

function toCardDraft(values) {
  return {
    number: values.number,
    expiry: values.expiry,
    cvv: values.cvv,
    last4: values.number.slice(-4)
  };
}

async function submitPaymentStep() {
  const { errors, values } = readPaymentForm();
  showFieldErrors(errors);
  const firstError = PAYMENT_FIELDS.find((id) => errors[id]);
  if (firstError) {
    showAlert('Please correct the highlighted fields.');
    $(firstError).focus();
    return;
  }

  if (!token) {
    openAuth(submitPaymentStep, 'Sign in to hold your room.');
    return;
  }
  if (!selectedRoom() || !state.travel) {
    goToStep(1);
    showAlert('Choose a room before entering payment details.');
    return;
  }

  // Keep the current hold when only the card changed. A second hold would block another room.
    const sameContact = state.contact &&
    state.contact.email === values.email &&
    state.contact.phone === values.phone;
  if (state.booking && sameContact) {
    cardDraft = toCardDraft(values);
    renderSummary();
    goToStep(4);
    return;
  }

  await withBusy($('submitStep2'), 'Holding your room…', async () => {
    try {
      await releaseHold();   // contact details changed: replace the old hold
      const booking = await api('/bookings', {
        method: 'POST',
        auth: true,
        body: {
          room_type_id: selectedRoom().room_type_id,
          check_in: state.travel.check_in,
          check_out: state.travel.check_out,
          guests: state.travel.guests,
          contact_email: values.email,
          contact_phone: values.phone
        }
      });

      state.booking = booking;
      state.contact = { email: values.email, phone: values.phone };
            state.holdExpiresAt = Date.now() + booking.hold_seconds * 1000;
      cardDraft = toCardDraft(values);
      startHoldTimer();
      renderSummary();
      goToStep(4);
    } catch (err) {
      if (err.status === 409) {
        // Another guest took the last room between the search and this request.
        state.selectedTypeId = null;
        goToStep(1);
        updateRoomSelection();
        renderSidebar();
        showAlert(`${err.message} Please choose another room type or different dates.`, 'warning');
        searchRooms({ silent: true });
      } else {
        reportError(err, submitPaymentStep);
      }
    }
  });
}

// ============================================================ Holds (reservations awaiting payment)
async function releaseHold() {
  if (!state.booking) return;
  const reservationId = state.booking.reservation_id;
  state.booking = null;
  state.contact = null;
  stopHoldTimer();
  renderSidebar();
  try {
    await api(`/bookings/${reservationId}`, { method: 'DELETE', auth: true });
  } catch (_) {
    // Already expired or cancelled on the server. Nothing else to release.
  }
}

function secondsLeft() {
  return Math.max(0, Math.ceil((state.holdExpiresAt - Date.now()) / 1000));
}

function startHoldTimer() {
  stopHoldTimer();
  tickHold();
  holdInterval = setInterval(tickHold, 1000);
}

function stopHoldTimer() {
  clearInterval(holdInterval);
  holdInterval = null;
}

function tickHold() {
  if (!state.booking) {
    stopHoldTimer();
    return;
  }
  const left = secondsLeft();
  $('holdTimer').textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
  if (left === 0) expireHold();
}

function expireHold() {
  stopHoldTimer();
  state.booking = null;
  state.contact = null;
  if (state.step === 4) {
    $('payBtn').disabled = true;
    showAlert('Your 15-minute hold has expired. Go back and submit your details again to request a new hold.', 'warning');
  }
  renderSidebar();
}

// ============================================================ Step 3: payment summary and capture
function renderSummary() {
  const b = state.booking;
  if (!b || !cardDraft) return;

  renderRows($('summaryList'), [
    ['Hotel', b.hotel],
    ['Primary guest', state.guest ? state.guest.full_name : '—'],
    ['Room', `${b.room_type}, room ${b.room_number}`],
    ['Dates', `${formatDate(b.check_in)} to ${formatDate(b.check_out)} (${b.nights} ${plural(b.nights, 'night')})`],
    ['Guests', `${b.guests} ${plural(b.guests, 'guest')}`],
    ['Email', state.contact.email],
    ['Phone', state.contact.phone],
    ['Card', `Ending in ${cardDraft.last4}`],
    ['Amount due', formatMoney(b.tariff.total), 'total']
  ]);

  $('payBtn').textContent = `Pay ${formatMoney(b.tariff.total)}`;
  $('payBtn').disabled = false;
}

async function payNow() {
  if (!state.booking || !cardDraft) {
    showAlert('Your hold is no longer active. Go back and submit your details again.', 'warning');
    return;
  }
  if (secondsLeft() === 0) {
    expireHold();
    return;
  }

  await withBusy($('payBtn'), 'Processing payment…', async () => {
    try {
      const result = await api('/payments', {
        method: 'POST',
        auth: true,
        body: {
          reservation_id: state.booking.reservation_id,
          card_number: cardDraft.number,
          expiry: cardDraft.expiry,
          cvv: cardDraft.cvv
        }
      });

      stopHoldTimer();
      state.receipt = { ...result, booking: state.booking };
      state.booking = null;
            state.contact = null;
      cardDraft = null;
      $('paymentForm').reset();
      renderReceipt(state.receipt);
      goToStep(5);
      renderSidebar();
    } catch (err) {
      if (err.status === 410) {
        expireHold();
      } else if (err.status === 402) {
        // The bill stays PENDING on the server, so the guest can retry with another card.
        showAlert(`${err.message} Use Back to change the card. Your room is still held.`);
      } else {
        reportError(err, payNow);
      }
    }
  });
}

async function cancelBooking() {
  if (!state.booking) return;
  if (!window.confirm('Cancel this booking? Your room will be released.')) return;
  await releaseHold();
  cardDraft = null;
  goToStep(1);
  searchRooms({ silent: true });
  showAlert('Your booking was cancelled and the room has been released.', 'success');
}

// ============================================================ Confirmation
function renderReceipt(receipt) {
  const box = $('receiptBody');
  box.replaceChildren();

  const badge = el('div', 'receipt-badge', '✓');
  badge.setAttribute('aria-hidden', 'true');
  const title = el('h2', '', 'Booking confirmed');
  title.id = 'receiptTitle';
  box.append(
    badge,
    title,
    el('p', 'muted', `Reservation #${receipt.reservation_id} is paid and confirmed. Keep the transaction reference for your records.`)
  );

  const list = el('dl', 'summary-list');
  box.append(list);
  renderRows(list, [
    ['Hotel', receipt.booking.hotel],
    ['Room', `${receipt.booking.room_type}, room ${receipt.booking.room_number}`],
    ['Dates', `${formatDate(receipt.booking.check_in)} to ${formatDate(receipt.booking.check_out)}`],
    ['Transaction ref', receipt.transaction_ref],
    ['Gateway ref', receipt.gateway_ref],
    ['Card', `Ending in ${receipt.card_last4}`],
    ['Amount paid', formatMoney(receipt.amount_paid), 'total']
  ]);
}

function resetFlow() {
  state.receipt = null;
  state.selectedTypeId = null;
  cardDraft = null;
  clearGuestForm();
  $('paymentForm').reset();
  showFieldErrors({});
  goToStep(1);
  renderRooms();
  renderSidebar();
  searchRooms({ silent: true });
}

// ============================================================ Order Review sidebar
function renderSidebar() {
  const order = state.booking || (state.receipt && state.receipt.booking) || null;
  const room = selectedRoom();
  const hasOrder = Boolean(order || room);

  $('orderEmpty').hidden = hasOrder;
  if (!hasOrder) {
    renderRows($('orderDetails'), []);
    return;
  }

  const t = order ? order.tariff : room.estimate;
  const nights = order ? order.nights : state.search.nights;
  const guests = order ? order.guests : state.travel.guests;
  const subtotal = toPaise(t.room_charge) + toPaise(t.booking_fee);

  renderRows($('orderDetails'), [
    ['Hotel', order ? order.hotel : state.search.hotel],
    ['Room', order ? `${order.room_type}, room ${order.room_number}` : room.name],
    ['Check-in', formatDate(order ? order.check_in : state.travel.check_in)],
    ['Check-out', formatDate(order ? order.check_out : state.travel.check_out)],
    ['Stay', `${nights} ${plural(nights, 'night')}, ${guests} ${plural(guests, 'guest')}`],
    ['Nightly rate', formatMoney(order ? order.nightly_rate : room.nightly_rate)],
    ['Room charge', formatMoney(t.room_charge)],
    ['Booking fee', formatMoney(t.booking_fee)],
    ['Subtotal', formatPaise(subtotal), 'subtotal'],
    ['Tax (12%)', formatMoney(t.tax)],
    ['Grand total', formatMoney(t.total), 'total']
  ]);
}

// ============================================================ Sign-in dialog
function setAuthMode(mode) {
  authMode = mode;
  const registering = mode === 'register';
  $('tabLogin').setAttribute('aria-selected', String(!registering));
  $('tabRegister').setAttribute('aria-selected', String(registering));
  document.querySelectorAll('[data-register-only]').forEach((node) => {
    node.hidden = !registering;
  });
  $('authTitle').textContent = registering ? 'Create your account' : 'Sign in to book';
  $('authSubmit').textContent = registering ? 'Create account' : 'Sign in';
  $('authPassword').setAttribute('autocomplete', registering ? 'new-password' : 'current-password');
  $('authError').textContent = '';
}

function openAuth(next = null, message = '') {
  pendingAction = next;
  setAuthMode('login');
  $('authError').textContent = message;
  if (!$('authDialog').open) $('authDialog').showModal();
  $('authEmail').focus();
}

async function handleAuth(event) {
  event.preventDefault();
  const registering = authMode === 'register';
  const email = $('authEmail').value.trim();
  const password = $('authPassword').value;
  const name = $('authName').value.trim();
  const phone = $('authPhone').value.replace(/[\s-]/g, '');

  let problem = '';
  if (!EMAIL_RE.test(email)) problem = 'Enter a valid email address.';
  else if (!password) problem = 'Enter your password.';
  else if (registering && name.length < 2) problem = 'Enter your full name.';
  else if (registering && !PHONE_RE.test(phone)) problem = 'Enter a phone number with 10 to 15 digits.';
  else if (registering && password.length < 8) problem = 'Password must be at least 8 characters.';
  if (problem) {
    $('authError').textContent = problem;
    return;
  }

  const payload = registering
    ? { full_name: name, email, phone, password }
    : { email, password };

  await withBusy($('authSubmit'), 'Please wait…', async () => {
    try {
      const data = await api(registering ? '/auth/register' : '/auth/login', {
        method: 'POST',
        body: payload
      });
      const next = pendingAction;
      pendingAction = null;
      setSession(data.token, { customer_id: data.customer_id, full_name: data.full_name, email });
      $('authDialog').close();
      if (next) next();
    } catch (err) {
      $('authError').textContent = err.message;
    }
  });
}

async function signOut() {
  await releaseHold();
  clearSession();
  clearGuestForm();
  cardDraft = null;
  state.receipt = null;
  goToStep(1);
  renderSidebar();
  showAlert('You have signed out.', 'success');
}

// ============================================================ Event wiring
function bindEvents() {
  $('travelForm').addEventListener('submit', (event) => {
    event.preventDefault();
    releaseHold();
    withBusy($('searchBtn'), 'Checking…', () => searchRooms());
  });

  ['checkIn', 'checkOut', 'guests'].forEach((id) => {
    $(id).addEventListener('change', onTravelEdited);
  });

  $('roomList').addEventListener('change', (event) => {
    if (event.target.name === 'roomType') onRoomPicked(Number(event.target.value));
  });

  $('toStep2').addEventListener('click', continueToPayment);
  $('backToStep1').addEventListener('click', () => goToStep(1));

  $('guestForm').addEventListener('submit', submitGuestForm);
  $('paymentForm').addEventListener('submit', (event) => {
    event.preventDefault();
    submitPaymentStep();
  });

  $('backToStep2').addEventListener('click', () => goToStep(2));
  $('backToPayment').addEventListener('click', () => goToStep(3));
  $('cancelHold').addEventListener('click', cancelBooking);
  $('payBtn').addEventListener('click', payNow);
  $('newBookingBtn').addEventListener('click', resetFlow);

  $('signInBtn').addEventListener('click', () => openAuth());
  $('signOutBtn').addEventListener('click', signOut);
  $('tabLogin').addEventListener('click', () => setAuthMode('login'));
  $('tabRegister').addEventListener('click', () => setAuthMode('register'));
  $('authForm').addEventListener('submit', handleAuth);
  $('authClose').addEventListener('click', () => $('authDialog').close());
  $('authDialog').addEventListener('close', () => {
    pendingAction = null;
  });

  // Input formatting. The server still validates everything.
  $('cardNumber').addEventListener('input', (event) => {
    const digits = event.target.value.replace(/\D/g, '').slice(0, 19);
    event.target.value = digits.replace(/(\d{4})(?=\d)/g, '$1 ');
  });

  $('cardExpiry').addEventListener('input', (event) => {
    const digits = event.target.value.replace(/\D/g, '').slice(0, 4);
    event.target.value = digits.length > 2 ? `${digits.slice(0, 2)}/${digits.slice(2)}` : digits;
  });

  $('cardCvv').addEventListener('input', (event) => {
    event.target.value = event.target.value.replace(/\D/g, '').slice(0, 4);
  });
}

// ============================================================ Startup
function init() {
  restoreSession();
  renderAccount();
  setupDates();
  setupGuestSelects();
  bindEvents();
  goToStep(1);
  renderSidebar();
  searchRooms({ silent: true });

  // Refresh availability once a minute while the guest is choosing a room.
  // Pause while a hold exists, because the guest's own hold would hide that room.
  liveInterval = setInterval(() => {
    if (state.step === 1 && !state.booking && state.search) {
      searchRooms({ silent: true });
    }
  }, LIVE_REFRESH_MS);
}

document.addEventListener('DOMContentLoaded', init);