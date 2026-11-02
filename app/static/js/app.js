(function () {
  var root = document.documentElement;
  var $ = function (s, c) { return (c || document).querySelector(s); };
  var $$ = function (s, c) { return Array.prototype.slice.call((c || document).querySelectorAll(s)); };

  // ---- theme ----
  function setTheme(t) {
    root.setAttribute('data-theme', t);
    try { localStorage.setItem('theme', t); } catch (e) {}
  }
  $$('[data-theme-toggle]').forEach(function (b) {
    b.addEventListener('click', function () {
      setTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  });

  // ---- mobile menu ----
  $$('[data-menu]').forEach(function (b) {
    b.addEventListener('click', function () { document.body.classList.toggle('menu-open'); });
  });
  var scrim = $('.scrim');
  if (scrim) scrim.addEventListener('click', function () { document.body.classList.remove('menu-open'); });

  // ---- local times ----
  $$('time[data-local]').forEach(function (t) {
    var d = new Date(t.getAttribute('datetime'));
    if (isNaN(d)) return;
    var mode = t.getAttribute('data-local');
    t.textContent = mode === 'date'
      ? d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
      : d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  });

  // ---- auto-dismiss success flashes ----
  $$('.flash-success').forEach(function (f) {
    setTimeout(function () { f.style.transition = 'opacity .4s'; f.style.opacity = '0';
      setTimeout(function () { f.remove(); }, 450); }, 6000);
  });

  // ---- password show/hide + strength ----
  $$('.toggle-pw').forEach(function (b) {
    b.addEventListener('click', function () {
      var i = b.parentNode.querySelector('input');
      i.type = i.type === 'password' ? 'text' : 'password';
      b.setAttribute('aria-pressed', i.type === 'text');
    });
  });
  var pw = $('[data-strength]');
  if (pw) {
    var bar = $('#strength-bar'), txt = $('#strength-text');
    pw.addEventListener('input', function () {
      var v = pw.value, s = 0;
      if (v.length >= 12) s++;
      if (v.length >= 16) s++;
      if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
      if (/\d/.test(v)) s++;
      if (/[^A-Za-z0-9]/.test(v)) s++;
      if (v.length < 12) s = Math.min(s, 1);
      var map = [['0%', '', ''], ['25%', '#dc2626', 'Weak'], ['50%', '#d97706', 'Fair'],
                 ['75%', '#0891b2', 'Good'], ['100%', '#059669', 'Strong'], ['100%', '#059669', 'Excellent']];
      var m = v ? map[Math.min(s, 5)] : map[0];
      bar.style.width = m[0]; bar.style.background = m[1]; txt.textContent = v ? m[2] : '';
    });
  }

  // ---- OTP input: digits only, auto submit when 6 ----
  var otp = $('.otp-input');
  if (otp) {
    otp.addEventListener('input', function () {
      otp.value = otp.value.replace(/\D/g, '').slice(0, 6);
      if (otp.value.length === 6 && otp.form.hasAttribute('data-autosubmit')) otp.form.requestSubmit();
    });
    if (!otp.form.querySelector('[name=password]')) otp.focus();
  }

  // ---- resend countdown ----
  var rb = $('[data-resend]');
  if (rb) {
    var left = parseInt(rb.getAttribute('data-resend'), 10) || 0, label = rb.textContent;
    var tick = function () {
      if (left > 0) { rb.disabled = true; rb.textContent = label + ' (' + left + 's)'; left--; setTimeout(tick, 1000); }
      else { rb.disabled = false; rb.textContent = label; }
    };
    tick();
  }

  // ---- dropzone ----
  var drop = $('.drop');
  if (drop) {
    var input = $('input[type=file]', drop), chosen = $('#chosen'), form = drop.closest('form');
    var maxMb = parseFloat(drop.getAttribute('data-max-mb')) || 16;
    var fmt = function (n) { return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB'; };
    var show = function () {
      var f = input.files[0];
      if (!f) { chosen.classList.remove('show'); return; }
      if (f.size > maxMb * 1048576) {
        alert('"' + f.name + '" is ' + fmt(f.size) + '. The limit is ' + maxMb + ' MB.');
        input.value = ''; chosen.classList.remove('show'); return;
      }
      $('#chosen-name').textContent = f.name + '  ·  ' + fmt(f.size);
      chosen.classList.add('show');
    };
    input.addEventListener('change', show);
    ['dragenter', 'dragover'].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (e) { drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove('over'); }); });
    drop.addEventListener('drop', function (ev) {
      if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; show(); }
    });
    form.addEventListener('submit', function () {
      $('.progress', form).classList.add('show');
      var b = $('#upload-btn'); b.disabled = true; b.lastChild.textContent = ' Encrypting…';
    });
  }

  // ---- generic submit-once buttons ----
  $$('form[data-once]').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = $('button[type=submit]', f); if (b) setTimeout(function () { b.disabled = true; }, 0);
    });
  });

  // ---- confirm dialogs ----
  $$('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!confirm(f.getAttribute('data-confirm'))) e.preventDefault();
    });
  });

  // ---- table search ----
  var q = $('#file-search');
  if (q) q.addEventListener('input', function () {
    var v = q.value.toLowerCase();
    $$('#files-body tr').forEach(function (r) { r.style.display = r.textContent.toLowerCase().indexOf(v) > -1 ? '' : 'none'; });
  });

  // ---- events filter ----
  $$('.pill[data-filter]').forEach(function (p) {
    p.addEventListener('click', function () {
      $$('.pill[data-filter]').forEach(function (x) { x.classList.remove('on'); });
      p.classList.add('on');
      var f = p.getAttribute('data-filter');
      $$('#events-body tr').forEach(function (r) { r.style.display = (f === 'all' || r.getAttribute('data-cat') === f) ? '' : 'none'; });
    });
  });

  // ---- landing page reveal animation (progressively enhanced) ----
  var revealItems = $$('.reveal-on-scroll');
  if (revealItems.length) {
    if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      var revealObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            revealObserver.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: '0px 0px -24px 0px' });
      revealItems.forEach(function (el) { revealObserver.observe(el); });
    } else {
      revealItems.forEach(function (el) { el.classList.add('is-visible'); });
    }
  }

})();