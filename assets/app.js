const $ = document.querySelector.bind(document);
const $$ = q => Array.from(document.querySelectorAll(q));

let cursor, startScroll, start, cursorPos;
let zoom = 1.00;
let focused = false;
let authed = false, authUser, admin;
let launchTime = Date.now();
let currMap;
const things = {};

// to be implemented - better filtering,
// although it could also be done via CSS properties
// and parent classes
const filters = {
  negative: true,
};

let countdownTimeout, mapTimeout;

const margin = 50;


// event times
const START_DAY = new Date('3/3/2020 12:00 CST').getTime();
const SECOND_WEEK = new Date('3/10/2020 12:00 CST').getTime();
const END_DATE = new Date('3/17/2020 12:00 CST').getTime();

const MIN = 60*1000;
const HOUR = 60*MIN;
const DAY = 24*HOUR;

// some helper functions for determining if we're on the right map
const isSecondWeek = () => Date.now() > SECOND_WEEK;
const isOver = () => Date.now() > END_DATE;
const isMapReadOnly = () => (isSecondWeek() ^ !currMap) || isOver();

const dataAge = [0, 0];
const dataCache = [[], []];

// change the display map, then fetch data
function setMap(isWorldsEdge) {
  currMap = isWorldsEdge;
  $('.map-parent').setAttribute('data-map', isWorldsEdge ? 'we' : 'kc');
  cancelAdd();
  getData(isWorldsEdge);

  // trigger a countdown if it's the right week
  clearTimeout(countdownTimeout);
  if (!isSecondWeek() && !currMap)
    countdown();
}

// countdown clock for impatient users
function countdown() {
  // ignore the clock if we're already in the second week
  $('.countdown-clock').display = !isSecondWeek() ? 'block' : 'none';

  // hide countdown on at end
  if (isSecondWeek()) {
    cancelAdd();
    return;
  }

  let text = '';

  const delta = (SECOND_WEEK - Date.now());

  // concatenate some times together
  if (delta > DAY)
    text += `${Math.floor(delta/DAY)}d `;

  if (delta > HOUR)
    text += `${Math.floor((delta % DAY)/HOUR)}h `;

  if (delta > MIN)
    text += `${Math.floor((delta % HOUR)/MIN)}m `;

  if (delta)
    text += `${Math.floor((delta % MIN)/1000)}s `;

  $('.countdown-clock').innerText = text;
  countdownTimeout = setTimeout(countdown, 1000);
}

// get an age string from integer seconds
function calcAge(ago) {
  let agoText;
  const delta = Date.now() - launchTime + ago;
  if (delta < 5000)
    agoText = 'moments';
  else if (delta < MIN)
    agoText = Math.round(delta/1000) + ' seconds';
  else if (delta < HOUR)
    agoText = Math.round(delta/MIN) + ' minutes';
  else if (delta < DAY)
    agoText = Math.round(delta/HOUR) + ' hours';
  else
    agoText = Math.floor(delta/DAY) + ' days';
  return agoText;
}

// check semi frequently for new map
function mapCheck() {
  // if we're already on kings canyon, this check is useless. exit.
  if (!currMap)
    return;

  // prevent a bunch of these from stacking up
  clearTimeout(mapTimeout);

  // determine if it's kings canyon day
  if (isSecondWeek()) {
    setMap(false);
  } else {

    // if we're not within an hour of the release time, check every 5 minutes
    // otherwise check every second :)
    mapTimeout = setTimeout(mapCheck, SECOND_WEEK - Date.now() > HOUR ? 5*MIN : 1000);
  }
}

const isFirefox = navigator.userAgent.toLowerCase().indexOf('firefox') > -1;
const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

// helper functions for getting scroll offset
const leftScroll = () => $('.map-child').scrollLeft,
  topScroll = () => $('.map-child').scrollTop;

function post(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type':'application/json'
    },
    body: JSON.stringify(body),
  });
}

function setCursor(x, y) {
  cursorPos = [x, y];
  $('.cursor.center').style.left =
  $('.cursor.top').style.left = x*2048 + 'px';
  $('.cursor.center').style.top =
  $('.cursor.left').style.top = y*2048 + 'px';

  $('.preview-menu').style.display = 'none';
}

// set the zoom level of the map
function modZoom(d) {
  if (isFirefox)
    return;
  zoom += d;
  zoom = Math.min(Math.max(zoom, 0.3), 8);
  $('.map-child').style.zoom = (zoom * 100) + '%';
  $$('.menu').forEach(m => m.style.zoom = ((1 / zoom) * 100) + '%');
  setMarkerPos($('.preview-menu'), true);
  $$('.marker').forEach(m => setMarkerPos(m));
  $('#zoomValue').innerText = Math.round(zoom * 100) + '%';
}

// move a marker based on zoom
function setMarkerPos(el, isPreview=false) {
  const x = parseFloat(el.getAttribute('x'));
  const y = parseFloat(el.getAttribute('y'));
  if (!el.classList.contains('ring')) {
    el.style.left = x * zoom * 2048 + 'px';
    el.style.top = y * zoom * 2048 + 'px';
    el.style.zoom = ((1 / zoom) * 100) + '%';
  } else {
    el.style.setProperty('--child-zoom', ((1 / zoom) * 100) + '%');
    el.style.left = x * 2048 + 'px';
    el.style.top = y * 2048 + 'px';
  }
}

// create a marker on the map
function addMarker(data) {
  if (data.thing === 'stab' && !data.color)
    data.color = 'gold';

  // if there's enough downvotes (20) and the ratio is bad enough, hide this thing
  if (data.bad > 10 && data.good/data.bad < 0.3 && filters.negative)
    return;

  const meta = things[data.thing];
  const el = document.createElement('div');
  el.className = `marker ${meta && meta.game ? data.thing : 'normal'} ${meta && meta.ammo || ''} ${data.color || ''}`;
  el.setAttribute('x', data.x);
  el.setAttribute('y', data.y);
  if (meta && meta.game)
    el.setAttribute('data-round', data.round);
  else
    el.innerText = data.thing;
  el.title = meta && meta.long;
  el.setAttribute('data-short', data.thing);
  el.setAttribute('data', JSON.stringify(data));
  setMarkerPos(el);
  $('.overlay').appendChild(el);
  return el;
}

// when one of the markers is clicked
function clickMarker(el) {
  cancelAdd();
  const preview = $('.preview-menu');
  const data = JSON.parse(el.getAttribute('data'));
  const meta = things[data.thing];

  preview.setAttribute('x', el.getAttribute('x'));
  preview.setAttribute('y', el.getAttribute('y'));

  $('#goodPoints').innerText = '+' + data.good;
  $('#badPoints').innerText = '-' + data.bad;
  $('#percent').innerText = (data.good + data.bad === 0 ? '?%' : Math.round(data.good/(data.good+data.bad)*100) + '%');
  $('#redditUser').innerText = data.user;
  $('#redditUser').href = 'https://reddit.com/u/' + data.user;

  $('#age').innerText = calcAge(data.ago);

  const className = `${meta.ammo || ''} ${data.color || ''}`.trim();
  $$('.selected-item').forEach(e => e.setAttribute('data-short', className ? '' : data.thing));

  $$('.item-short').forEach(el => {
    el.innerText = data.thing;
    el.className = 'item-short ' + className;
  });
  $$('.item-long').forEach(el => {
    el.innerText = meta.long;
    el.className = 'item-long ' + className;
  });

  const vote = (uuid, vote) => e => {
    if (vote === data.vote) {
      if (vote === 0)
        return;
      vote = 0;
    }

    e.preventDefault();
    post('/api/vote', { uuid, vote })
      .then(r => {
        if (vote === 0) {
          if (data.vote !== 0)
          data[data.vote > 0 ? 'good' : 'bad'] --;
        }
        else if (vote !== 0) {
          data[vote > 0 ? 'good' : 'bad'] ++;
          if (data.vote !== 0) {
            data[data.vote > 0 ? 'good' : 'bad'] --;
          }
        }
        data.vote = vote;
        el.setAttribute('data', JSON.stringify(data));
        $('#goodPoints').innerText = '+' + data.good;
        $('#badPoints').innerText = '-' + data.bad;
        $('#upvoteButton').style.textDecoration = vote >= 0 ? 'underline' : 'none';
        $('#downvoteButton').style.textDecoration = vote <= 0 ? 'underline' : 'none';
      })
      .catch(console.error)
  };

  const remove = e => {
    post('/api/delete', { uuid: data.uuid })
      .then(r => {
        $('.overlay').removeChild(el);
        $('.preview-menu').style.display = 'none';
      })
      .catch(console.error);
  }

  $('#upvoteButton').onclick = vote(data.uuid, 1);
  $('#downvoteButton').onclick = vote(data.uuid, -1);
  $('#upvoteButton').style.textDecoration = data.vote >= 0 ? 'underline' : 'none';
  $('#downvoteButton').style.textDecoration = data.vote <= 0 ? 'underline' : 'none';

  $('#deleteButton').style.display = data.user === authUser || admin ? 'inline' : 'none';
  $('#deleteButton').onclick = remove;
  $('.preview-menu .action-items').style.display = authUser ? 'inline' : 'none';

  preview.style.display = 'block';
  setMarkerPos(preview, true);
}

function showCooldown() {
  $('#addButton').classList.add('disabled');
  const COOLDOWN_TIME = 10;
  for (let i = 0; i < COOLDOWN_TIME; i++) {
    const t = i;
    setTimeout(
      () => $('#addButton').innerText = `wait ${COOLDOWN_TIME-t} seconds...`,
      i * 1000
    );
  }
  setTimeout(() => {
    $('#addButton').innerText = 'add';
    $('#addButton').classList.remove('disabled');
  }, 1000 * COOLDOWN_TIME);
}

// post something new to the map
function postData(short, pos, data) {
  post('/api/data', {
    id: short,
    x: pos[0],
    y: pos[1],
    color: data.color,
    round: data.round,
  })
    .then(r => Promise.all([r.status, r.json()]))
    .then(([status, r]) => {
      if (r.message === 'Unauthorized')
        location.reload();

      if (status === 201)
        showCooldown();

      if (status >= 400)
        return;

      r.ago = -launchTime;
      clickMarker(addMarker(r));
    })
    .catch(console.error);
}

// fetch all the data from the server
function getData(isWorldsEdge) {
  const map = isWorldsEdge ? 0 : 1;
  const renderData = r => {
    const overlay = $('.overlay');
    let child = overlay.lastElementChild;
    while (child) {
      overlay.removeChild(child);
      child = overlay.lastElementChild;
    }
    r.forEach(addMarker);
  };

  // check if we fetched this data less than 10 seconds ago
  if (Date.now() - dataAge[map] < 10000) {
    launchTime = dataAge[map];
    renderData(dataCache[map]);
    return;
  }

  return fetch('/api/data'+(isWorldsEdge ? '' : '?kc=yes'))
    .then(r => r.json())
    .then(r => {
      console.log('all items:', r);
      launchTime = Date.now();
      dataAge[map] = launchTime;
      dataCache[map] = r;

      renderData(r);
    })
}

// check if we need to sign in to add stuff to the map
function authCheck() {
  fetch('/auth/check')
    .then(r => r.json())
    .then(r => {
      console.log('auth data:', r);
      if (r.banned) {
        alert('You were banned. Please be respectful next time.');
        throw 'rip';
        return;
      }

      if (r.isAuth) {
        $('.addition-menu.no-auth').style.display = 'none';
        $('.addition-menu.authed').style.display = 'block';
        authed = true;
        $('#logout').style.display = 'inline';
        authUser = r.user;
        admin = r.admin;
      } else {
        $('.addition-menu.no-auth').style.display = 'block';
        $('.addition-menu.authed').style.display = 'none';
      }
      // refresh
      setMap(!isSecondWeek());
      mapCheck();
    })
    // handle offline message
    .catch(console.error);
}

const itemInit = el => {
  const className = el.className;
  const short = el.getAttribute('data-short');
  const isGame = el.getAttribute('data-game') === 'true';
  const long = el.getAttribute('data-name');
  let chosenRound;

  // add the entry to our list
  things[short] = {
    long,
    ammo: el.classList.length === 3 ? el.classList[2] : undefined,
    game: isGame,
  };

  return e => {
    e.preventDefault();
    // if we're on the wrong map (second week and worlds edge or first week and kings canyon)
    // prevent users from adding to the map (entries are time based, not map indexed)

    if (authed && focused && !isMapReadOnly()) {
      $('.state-0').style.display = 'none';
      $('.state-1').style.display = isGame ? 'none' : 'block';
      $('.state-2').style.display = isGame ? 'block' : 'none';

      $$('.cursor .marker').forEach(e => e.style.display = 'none');

      if (isGame) {
        $(`.cursor .marker.${short}`).style.display = 'block';
        $(`.care-note`).style.display = short === 'care' ? 'block' : 'none';

        $$('.rounds a').forEach(el => {
          el.classList.remove('unselected');
          el.onclick = () => {
            $('#addButton').style.display = 'inline';
            chosenRound = Number(el.getAttribute('data-round'));
            if (short === 'ring')
              $('.cursor .marker.ring').setAttribute('data-round', chosenRound);
            // set ring display size
            $$('.rounds a').forEach(b => {
                b.classList[el === b ? 'remove' : 'add']('unselected');
            });
          };
        });
      } else {
        $('.cursor .marker.normal').style.display = 'block';
        $('#addButton').style.display = 'inline';
      }

      $('#addButton').onclick = e => {
        console.log('adding', short, 'at', ...cursorPos);
        postData(short, cursorPos, {
          color: el.classList.length === 2 ? el.classList[1] : undefined,
          round: chosenRound,
        });
      };

      $$('.selected-item').forEach(e => e.setAttribute('data-short', className.replace('item', '') ? '' : short));
      $$('.item-short').forEach(e => {
        e.innerText = short;
        e.className = 'item-short ' + className;
      });
      $$('.item-long').forEach(e => {
        e.innerText = long;
        e.className = 'item-long ' + className;
      });
    } else {
      const menu = $(`.item.filtered`);
      const isFiltered = menu && menu.getAttribute('data-short') === short;
      // remove focus on other kinds of markers
      $$(`.filtered:not([data-short="${short}"])`)
        .forEach(el => el.classList.remove('filtered'));

      // toggle focus on this kind of marker based on the menu focus
      // (adding new items prevents us from using .toggle)
      $$(`[data-short="${short}"]`)
        .forEach(el => el.classList[isFiltered ? 'remove' : 'add']('filtered'));
    }
  }
}

function cancelAdd(e) {
  if (e)
    e.preventDefault();
  focused = false;
  setCursor(-1, -1);
}

// handle zoom button clicks
const zoomHelper = v => e => {e.preventDefault();modZoom(v);}

function wheelListener(e) {
  if(isFirefox)
    return;

  const [x, y] = shiftCoords(e.pageX, e.pageY)

  // calculate the mouse position after zooming
  const oldPos = [x/zoom + leftScroll(), y/zoom + topScroll()];
  modZoom(Math.sign(e.deltaY) * (zoom > 1.5 ? -0.4 : -0.1));
  const newPos = [x/zoom + leftScroll(), y/zoom + topScroll()];

  // offset the scrolling by the difference
  const diff = [newPos[0] - oldPos[0], newPos[1] - oldPos[1]];
  $('.map-child').scrollLeft -= diff[0];
  $('.map-child').scrollTop -= diff[1];

  // re-adjust the starting position of the cursor for this drag
  if (cursor) {
    start = shiftCoords(e.pageX, e.pageY);
    cursor = shiftCoords(e.pageX, e.pageY);
    startScroll = [leftScroll(), topScroll()];
  }
};

function shiftCoords(x, y) {
  // map rectangle size
  const rect = $('.map-child').getBoundingClientRect();

  // page size
  const pageWidth = document.body.clientWidth,
    pageHeight = document.body.clientHeight;

  // determine space between edge of page and the map square
  const marginX = pageWidth - rect.width*zoom,
    marginY = pageHeight - rect.height*zoom;

  // only offset when the X or Y axis of the map is off the page
  return [
    x + (marginX < 0 ? 0 : -marginX/2),
    y + (marginY < 0 ? 0 : -marginY/2),
  ];
}

function clickView(target, x, y) {
  if (target && target.classList.contains('marker')) {
    clickMarker(target);
    start = cursor = null;
    return;
  }

  if (!target || target.className !== 'overlay') {
    start = cursor = null;
    if (isMobile) {
      target.click();
    }
    return;
  }

  $('.overlay').blur();

  start = cursor = shiftCoords(x, y);

  startScroll = [leftScroll(), topScroll()];
}

function mouseDownListener(e) {
  if (e.button !== 0) return;
  dragDistance = 0;
  clickView(e.target, e.pageX, e.pageY)
}

let multiTouchStart, multiTouchPos;
function touchDownListener(e) {
  e.preventDefault();

  if (e.touches.length === 1) {
    const touch = e.touches[0];
    // make it full screen please!
    try {
      if(document.documentElement.requestFullscreen)
        document.documentElement.requestFullscreen();
    } catch (e) {console.warn(e);}
    dragDistance = 0;
    clickView(touch.target, touch.pageX, touch.pageY);
  } else if (e.touches.length === 2) {
    multiTouchStart = multiTouchPos = [
      shiftCoords(e.touches[0].pageX, e.touches[0].pageY),
      shiftCoords(e.touches[1].pageX, e.touches[1].pageY),
    ];
    startScroll = [leftScroll(), topScroll()];
  }
}

function clickUpView(x, y, noshift=false) {
  $('.map-child').style.cursor = 'default';
  if (!cursor)
    return;

  [x, y] = noshift ? [x, y] : shiftCoords(x, y);

  if (dragDistance < 5) {
    const renderPos = [x/zoom + $('.map-child').scrollLeft, y/zoom + $('.map-child').scrollTop]
    if (renderPos[0] < margin || renderPos[1] < margin || renderPos[0] > 2048-margin || renderPos[1] > 2048-margin)
      return;
    const dataPos = [renderPos[0]/(2048), renderPos[1]/(2048)];

    const readOnly = isMapReadOnly();
    if (!focused) {
      $$('.cursor .marker').forEach(e => e.style.display = 'none');
      $('.state-0').style.display = readOnly ? 'none' : 'block';
      $('.state-1').style.display = 'none';
      $('.state-2').style.display = 'none';
      $('.state-3').style.display = readOnly ? 'block' : 'none';
      $('#addButton').style.display = 'none';
      focused = true;
    }
    setCursor(...dataPos);
  }

  cursor = undefined;
  start = undefined;
}

function mouseUpListener(e) {
  if (e.button !== 0) return;
  $('.map-child').style.cursor = 'default';
  if (!cursor)
    return;

  clickUpView(e.pageX, e.pageY);
}

function touchUpListener(e) {
  e.preventDefault();

  if (e.touches.length === 0) {
    if (!cursor)
      return;

    clickUpView(...cursor, true);
  }
  multiTouchStart = multiTouchPos = startScroll = undefined;
}

function shiftView(x, y) {
  [x, y] = shiftCoords(x, y);

  // move the map based on how far the mouse moved and how zoomed in user is
  // I use a "startScroll" and "start" variable because re-calculating the scroll and mouse position
  // cause a bit of drift and I was very OCD about it.
  const diff = [(x-start[0])/zoom, (y-start[1])/zoom];
  $('.map-child').scrollLeft = startScroll[0]-diff[0];
  $('.map-child').scrollTop = startScroll[1]-diff[1];
  dragDistance += Math.hypot(x-cursor[0], y-cursor[1]);
  cursor = [x, y];

  // set the cursor to a little hand :)
  $('.map-child').style.cursor = 'grab';
}

// left mouse click
function moveListener(e) {
  if (!cursor)
    return;

  shiftView(e.pageX, e.pageY)
}

let dragDistance = 0;
function touchMoveListener(e) {
  if (e.touches.length === 1 && start && cursor) {
    multiTouchStart = multiTouchPos = undefined;
    if (!cursor || !start)
      return;

    const touch = e.touches[0];
    shiftView(touch.pageX, touch.pageY)
  } else if (e.touches.length === 2 && multiTouchStart) {
    touchCurr = [
      shiftCoords(e.touches[0].pageX, e.touches[0].pageY),
      shiftCoords(e.touches[1].pageX, e.touches[1].pageY),
    ];

    // helper to get distance between two touches
    const getDist = arr =>
      Math.hypot(arr[0][0]-arr[1][0],arr[0][1]-arr[1][1]);

    // get midpoint of two coords
    const getMidpoint = (a, b) => [(a[0]+b[0])/2, (a[1]+b[1])/2];

    const startDist = getDist(multiTouchStart);
    const lastDist = getDist(multiTouchPos);
    const currDist = getDist(touchCurr);
    const startMidpoint = getMidpoint(...multiTouchPos);
    const currMidpoint = getMidpoint(...touchCurr);

    window.requestAnimationFrame(() => {
      // offset the scrolling by the difference
      const diff = [currMidpoint[0] - startMidpoint[0], currMidpoint[1] - startMidpoint[1]];
      dragDistance += getDist(diff);
      // calculate the mouse position after zooming
      const oldPos = [currMidpoint[0]/zoom + leftScroll(), currMidpoint[1]/zoom + topScroll()];
      modZoom(currDist/startDist - lastDist/startDist);
      const newPos = [currMidpoint[0]/zoom + leftScroll(), currMidpoint[1]/zoom + topScroll()];

      // shift scroll by the mouse movement and the change due to zoom
      $('.map-child').scrollLeft += - diff[0]/zoom - (newPos[0] - oldPos[0]);
      $('.map-child').scrollTop += - diff[1]/zoom - (newPos[1] - oldPos[1]);
      multiTouchPos = touchCurr;
    });
  }
}

document.addEventListener('DOMContentLoaded', e => {
  $('#zoomPlus').addEventListener('click', zoomHelper(0.1));
  $('#zoomMinus').addEventListener('click', zoomHelper(-0.1));
  $('.map-child').addEventListener('wheel', wheelListener);
  $('.map-child').addEventListener('mousedown', mouseDownListener);
  $('.map-child').addEventListener('mouseup', mouseUpListener);
  $('.map-child').addEventListener('mouseleave', mouseUpListener);
  $('.map-child').addEventListener('mousemove', moveListener);

  $('.map-child').addEventListener('touchstart', touchDownListener);
  $('.map-child').addEventListener('touchend', touchUpListener);
  $('.map-child').addEventListener('touchcancel', touchUpListener);
  $('.map-child').addEventListener('touchmove', touchMoveListener);

  $('#cancelButton').addEventListener('click', cancelAdd);
  $('#closeButton').addEventListener('click', () => $('.preview-menu').style.display = 'none');

  $('.map-button.kc').onclick = () => setMap(true);
  $('.map-button.we').onclick = () => setMap(false);

  $$('.items-list .item').forEach(i =>
    i.addEventListener('click', itemInit(i)));

  // handle awkward bottom menu issues on mobile
  if (isMobile)
    $$('.items-title').forEach(i => {
      i.parentNode.classList.add('closed');
      i.onclick = () => {
        const isOpen = i.parentNode.classList.contains('open');
        $$('.items-category').forEach(j => j.classList.add('closed'));
        if (!isOpen) {
          i.parentNode.classList.remove('closed');
          i.parentNode.classList.add('open');
        } else {
          i.parentNode.classList.remove('open');
        }
      };
    });

  setCursor(-1, -1);
  $('.map-child').scrollLeft = 1024 - $('.map-child').clientWidth / 2;
  $('.map-child').scrollTop = 1024 - $('.map-child').clientHeight / 2;

  authCheck();
  setInterval(authCheck, 30 * 60 * 60 * 1000);
});