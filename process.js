/* ================================================================
   CLASSIC CRYPTIC — process.js
   Berisi semua logika aplikasi:
     1. Metadata algoritma
     2. State aplikasi
     3. Implementasi cipher (Caesar, Rail Fence, Vigenère,
        Monoalphabetic, Playfair, Hill, Scytale, Columnar)
     4. Fungsi proses utama
     5. Render selector algoritma
     6. Render Key Controller
     7. Mode toggle
     8. Helper workspace (clear, copy, swap, sample)
     9. Cryptanalysis (frekuensi, IoC, word pattern)
    10. Visualisasi step-by-step
    11. Init & live update
   ================================================================ */

/* ----------------------------------------------------------------
   1. ALGORITHM METADATA
   ---------------------------------------------------------------- */
const ALGORITHMS = [
  {
    id: 'caesar',
    name: 'Caesar',
    icon: '🔄',
    type: 'SUB',
    badge: 'badge-sub',
    typeLabel: 'Substitution',
    desc: 'Each letter is shifted by a fixed number of positions in the alphabet. One of the oldest and simplest ciphers, used by Julius Caesar.',
    tags: ['Classic', 'Shift', 'Monoalpha'],
  },
  {
    id: 'rail',
    name: 'Rail Fence',
    icon: '⚡',
    type: 'TRANS',
    badge: 'badge-trans',
    typeLabel: 'Transposition',
    desc: 'Letters are written diagonally across a number of "rails" (rows), then read off row by row to create the ciphertext.',
    tags: ['Zigzag', 'Transposition', 'Pattern'],
  },
  {
    id: 'vigenere',
    name: 'Vigenère',
    icon: '🔑',
    type: 'POLY',
    badge: 'badge-poly',
    typeLabel: 'Polyalphabetic',
    desc: 'Uses a keyword to determine shift amounts, cycling through the key letters. Resistant to simple frequency analysis.',
    tags: ['Keyword', 'Polyalpha', 'Historical'],
  },
  {
    id: 'mono',
    name: 'Monoalpha',
    icon: '🔤',
    type: 'SUB',
    badge: 'badge-sub',
    typeLabel: 'Substitution',
    desc: 'Each letter is replaced by a unique fixed substitute. The substitution alphabet is defined in the key controller.',
    tags: ['Fixed Sub', 'Alphabet', 'Custom'],
  },
  {
    id: 'playfair',
    name: 'Playfair',
    icon: '⬛',
    type: 'POLY',
    badge: 'badge-poly',
    typeLabel: 'Digraph Substitution',
    desc: 'Encrypts pairs of letters (digraphs) using a 5×5 key square. Rules depend on row, column, or rectangle position.',
    tags: ['Digraph', '5x5 Grid', 'Pairs'],
  },
  {
    id: 'hill',
    name: 'Hill',
    icon: '🔢',
    type: 'POLY',
    badge: 'badge-poly',
    typeLabel: 'Matrix Cipher',
    desc: 'Uses linear algebra — multiplies vector of plaintext letters by a key matrix (mod 26). A polygraphic cipher.',
    tags: ['Matrix', 'Linear Algebra', 'Polygraphic'],
  },
  {
    id: 'scytale',
    name: 'Scytale',
    icon: '📜',
    type: 'TRANS',
    badge: 'badge-trans',
    typeLabel: 'Transposition',
    desc: 'Ancient Spartan tool — text is written across a rod, then unwound. The key is the number of rows (rod diameter).',
    tags: ['Ancient', 'Rod', 'Columnar'],
  },
  {
    id: 'columnar',
    name: 'Columnar',
    icon: '📋',
    type: 'TRANS',
    badge: 'badge-trans',
    typeLabel: 'Transposition',
    desc: 'Text is written into rows in a grid, then columns are read in an order determined by a keyword.',
    tags: ['Keyword', 'Grid', 'Column Order'],
  },
];

/* ----------------------------------------------------------------
   2. APPLICATION STATE
   ---------------------------------------------------------------- */
const state = {
  algo: 'caesar',
  mode: 'encrypt', // 'encrypt' | 'decrypt'
  // Kunci per algoritma
  caesarShift: 3,
  railRails: 3,
  vigenereKey: 'KEY',
  monoSubMap: genDefaultMono(),
  playfairKey: 'PLAYFAIR',
  hillMatrix: [[3,3],[2,5]], // 2x2 default
  hillSize: 2,
  scytaleRows: 4,
  columnarKey: 'SECRET',
  // State visualisasi
  vizSteps: [],
  vizCurrentStep: 0,
  vizAutoTimer: null,
};

/** Buat peta substitusi default untuk Monoalphabetic (keyboard layout) */
function genDefaultMono() {
  const map = {};
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const sub   = 'QWERTYUIOPASDFGHJKLZXCVBNM';
  for (let i = 0; i < 26; i++) map[alpha[i]] = sub[i];
  return map;
}

/* ----------------------------------------------------------------
   3. CIPHER IMPLEMENTATIONS
   ---------------------------------------------------------------- */

/** --- CAESAR ---
 *  Geser setiap huruf sebanyak `shift` posisi dalam alfabet.
 *  Untuk dekripsi, shift dibalik menjadi (26 - shift).
 */
function caesarCipher(text, shift, decrypt) {
  const s = decrypt ? (26 - (shift % 26)) : (shift % 26);
  return text.toUpperCase().replace(/[A-Z]/g, c => {
    return String.fromCharCode(((c.charCodeAt(0) - 65 + s) % 26) + 65);
  });
}

/** --- RAIL FENCE ENCRYPT ---
 *  Tulis karakter secara zigzag ke sejumlah rail,
 *  lalu baca tiap rail dari kiri ke kanan.
 */
function railFenceEncrypt(text, rails) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (rails < 2) return clean;
  const fence = Array.from({ length: rails }, () => []);
  let rail = 0, dir = 1;
  for (const ch of clean) {
    fence[rail].push(ch);
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  return fence.map(r => r.join('')).join('');
}

/** --- RAIL FENCE DECRYPT ---
 *  Rekonstruksi pola zigzag, lalu isi ulang dari ciphertext.
 */
function railFenceDecrypt(text, rails) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const n = clean.length;
  if (rails < 2) return clean;
  // Tentukan pola rail untuk tiap posisi
  const pattern = [];
  let rail = 0, dir = 1;
  for (let i = 0; i < n; i++) {
    pattern.push(rail);
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  // Hitung jumlah karakter per rail
  const counts = new Array(rails).fill(0);
  pattern.forEach(r => counts[r]++);
  // Bagi ciphertext menjadi segmen per rail
  const segments = [];
  let pos = 0;
  for (let r = 0; r < rails; r++) {
    segments.push(clean.substring(pos, pos + counts[r]).split(''));
    pos += counts[r];
  }
  // Rakit ulang sesuai pola
  const pointers = new Array(rails).fill(0);
  let result = '';
  for (let i = 0; i < n; i++) {
    const r = pattern[i];
    result += segments[r][pointers[r]++];
  }
  return result;
}

/** --- VIGENÈRE ---
 *  Tiap huruf digeser berdasarkan huruf kunci yang berulang.
 */
function vigenereCipher(text, key, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k.length) return clean;
  let result = '', ki = 0;
  for (const ch of clean) {
    const shift = k[ki % k.length].charCodeAt(0) - 65;
    const code  = ch.charCodeAt(0) - 65;
    const enc   = decrypt
      ? ((code - shift + 26) % 26)
      : ((code + shift) % 26);
    result += String.fromCharCode(enc + 65);
    ki++;
  }
  return result;
}

/** --- MONOALPHABETIC ---
 *  Tiap huruf diganti dengan pasangan tetap dari subMap.
 *  Untuk dekripsi, map dibalik.
 */
function monoCipher(text, subMap, decrypt) {
  let map = subMap;
  if (decrypt) {
    const rev = {};
    for (const [k, v] of Object.entries(subMap)) rev[v] = k;
    map = rev;
  }
  return text.toUpperCase().replace(/[A-Z]/g, c => map[c] || c);
}

/** --- PLAYFAIR: Bangun kisi 5×5 dari kunci ---
 *  Huruf J digabung dengan I. Duplikat dihapus.
 */
function buildPlayfairSquare(key) {
  const seen = new Set();
  const sq = [];
  const clean = (key.toUpperCase() + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')
    .replace(/J/g, 'I')
    .replace(/[^A-Z]/g, '');
  for (const ch of clean) {
    if (!seen.has(ch)) { seen.add(ch); sq.push(ch); }
  }
  // Susun jadi grid 5×5
  const grid = [];
  for (let r = 0; r < 5; r++) grid.push(sq.slice(r * 5, r * 5 + 5));
  return grid;
}

/** Cari posisi huruf di kisi Playfair */
function findInGrid(grid, ch) {
  for (let r = 0; r < 5; r++)
    for (let c = 0; c < 5; c++)
      if (grid[r][c] === ch) return [r, c];
  return [-1, -1];
}

/** --- PLAYFAIR ---
 *  Enkripsi/dekripsi pasangan huruf (digraf) menggunakan kisi 5×5.
 */
function playfairCipher(text, key, decrypt) {
  const grid = buildPlayfairSquare(key);
  let clean = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
  // Siapkan digraf
  const digraphs = [];
  let i = 0;
  while (i < clean.length) {
    const a = clean[i];
    const b = i + 1 < clean.length ? clean[i + 1] : 'X';
    if (a === b) { digraphs.push([a, 'X']); i++; }
    else { digraphs.push([a, b]); i += 2; }
  }
  if (digraphs.length === 0) return '';
  const d = decrypt ? -1 : 1;
  let result = '';
  for (const [a, b] of digraphs) {
    const [ra, ca] = findInGrid(grid, a);
    const [rb, cb] = findInGrid(grid, b);
    if (ra === rb) {
      // Baris sama → geser kolom
      result += grid[ra][(ca + d + 5) % 5] + grid[rb][(cb + d + 5) % 5];
    } else if (ca === cb) {
      // Kolom sama → geser baris
      result += grid[(ra + d + 5) % 5][ca] + grid[(rb + d + 5) % 5][cb];
    } else {
      // Persegi panjang → tukar sudut
      result += grid[ra][cb] + grid[rb][ca];
    }
  }
  return result;
}

/* --- HILL: Fungsi-fungsi aljabar linear mod 26 --- */

/** Cari invers modular a^-1 mod m (brute force, m=26) */
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) {
    if ((a * x) % m === 1) return x;
  }
  return -1; // tidak ada invers
}

/** Perkalian matriks × vektor mod 26 */
function matMulMod(mat, vec, mod) {
  return mat.map(row => row.reduce((acc, v, i) => acc + v * vec[i], 0) % mod);
}

/** Invers matriks 2×2 mod 26 */
function mat2x2Inv(mat) {
  const [[a,b],[c,d]] = mat;
  const det = ((a*d - b*c) % 26 + 26) % 26;
  const detInv = modInverse(det, 26);
  if (detInv === -1) return null;
  return [
    [((d * detInv) % 26 + 26) % 26,  ((-b * detInv) % 26 + 26) % 26],
    [((-c * detInv) % 26 + 26) % 26,  ((a * detInv) % 26 + 26) % 26],
  ];
}

/** Determinan matriks 3×3 */
function mat3x3Det(m) {
  return m[0][0]*(m[1][1]*m[2][2]-m[1][2]*m[2][1])
       - m[0][1]*(m[1][0]*m[2][2]-m[1][2]*m[2][0])
       + m[0][2]*(m[1][0]*m[2][1]-m[1][1]*m[2][0]);
}

/** Matriks adjoin (transpose kofaktor) dari matriks 3×3 */
function mat3x3Adj(m) {
  const adj = [];
  for (let r = 0; r < 3; r++) {
    adj.push([]);
    for (let c = 0; c < 3; c++) {
      // Hitung minor 2×2
      const minor = [];
      for (let i = 0; i < 3; i++) {
        if (i === r) continue;
        const row = [];
        for (let j = 0; j < 3; j++) {
          if (j === c) continue;
          row.push(m[i][j]);
        }
        minor.push(row);
      }
      const det2 = minor[0][0]*minor[1][1] - minor[0][1]*minor[1][0];
      adj[r].push(((r + c) % 2 === 0 ? 1 : -1) * det2);
    }
  }
  // Transpose adjoin
  return adj[0].map((_, c) => adj.map(row => row[c]));
}

/** Invers matriks 3×3 mod 26 */
function mat3x3Inv(m) {
  const det = ((mat3x3Det(m) % 26) + 26) % 26;
  const detInv = modInverse(det, 26);
  if (detInv === -1) return null;
  const adj = mat3x3Adj(m);
  return adj.map(row => row.map(v => ((v * detInv) % 26 + 26) % 26));
}

/** --- HILL ---
 *  Bagi plaintext menjadi blok ukuran `size`,
 *  kalikan tiap blok dengan matriks kunci mod 26.
 */
function hillCipher(text, matrix, size, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  // Padding agar panjang kelipatan size
  let padded = clean;
  while (padded.length % size !== 0) padded += 'X';

  let mat = matrix;
  if (decrypt) {
    mat = size === 2 ? mat2x2Inv(matrix) : mat3x3Inv(matrix);
    if (!mat) return 'ERROR: Key matrix not invertible mod 26';
  }

  let result = '';
  for (let i = 0; i < padded.length; i += size) {
    const vec = Array.from({ length: size }, (_, j) => padded.charCodeAt(i + j) - 65);
    const out = matMulMod(mat, vec, 26).map(n => String.fromCharCode(((n % 26) + 26) % 26 + 65));
    result += out.join('');
  }
  return result;
}

/** --- SCYTALE ENCRYPT ---
 *  Tulis baris per baris ke grid, baca kolom per kolom.
 */
function scytaleEncrypt(text, rows) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const cols = Math.ceil(clean.length / rows);
  let padded = clean;
  while (padded.length < rows * cols) padded += 'X';
  let result = '';
  for (let c = 0; c < cols; c++)
    for (let r = 0; r < rows; r++)
      result += padded[r * cols + c];
  return result;
}

/** --- SCYTALE DECRYPT ---
 *  Tulis kolom per kolom, baca baris per baris.
 */
function scytaleDecrypt(text, rows) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const cols = Math.ceil(clean.length / rows);
  const grid = Array.from({ length: rows }, () => new Array(cols).fill(''));
  let idx = 0;
  for (let c = 0; c < cols; c++)
    for (let r = 0; r < rows; r++)
      if (idx < clean.length) grid[r][c] = clean[idx++];
  return grid.map(r => r.join('')).join('');
}

/** --- COLUMNAR TRANSPOSITION ENCRYPT ---
 *  Tulis teks ke grid, baca kolom sesuai urutan alfabet kunci.
 */
function columnarEncrypt(text, key) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k.length) return clean;
  const cols = k.length;
  const rows = Math.ceil(clean.length / cols);
  let padded = clean;
  while (padded.length < rows * cols) padded += 'X';
  // Urutan kolom berdasarkan alfabetis huruf kunci
  const order = [...k].map((ch, i) => [ch, i]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0).map(([, i]) => i);
  let result = '';
  for (const col of order) {
    for (let r = 0; r < rows; r++) result += padded[r * cols + col];
  }
  return result;
}

/** --- COLUMNAR TRANSPOSITION DECRYPT --- */
function columnarDecrypt(text, key) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k.length) return clean;
  const cols = k.length;
  const rows = Math.ceil(clean.length / cols);
  const order = [...k].map((ch, i) => [ch, i]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0).map(([, i]) => i);
  // Rekonstruksi kolom dari ciphertext
  const colData = {};
  let pos = 0;
  for (const col of order) {
    colData[col] = clean.substring(pos, pos + rows);
    pos += rows;
  }
  let result = '';
  for (let r = 0; r < rows; r++)
    for (let c = 0; c < cols; c++)
      result += colData[c][r] || '';
  return result;
}

/* ----------------------------------------------------------------
   4. MASTER PROCESS FUNCTION
   Dipanggil setiap kali input atau konfigurasi berubah.
   ---------------------------------------------------------------- */
function processText() {
  const input = document.getElementById('input-text').value;
  const dec = state.mode === 'decrypt';
  let output = '';
  let errMsg = '';

  try {
    switch (state.algo) {
      case 'caesar':
        output = caesarCipher(input, state.caesarShift, dec);
        break;
      case 'rail':
        output = dec ? railFenceDecrypt(input, state.railRails)
                     : railFenceEncrypt(input, state.railRails);
        break;
      case 'vigenere':
        output = vigenereCipher(input, state.vigenereKey, dec);
        break;
      case 'mono':
        output = monoCipher(input, state.monoSubMap, dec);
        break;
      case 'playfair':
        output = playfairCipher(input, state.playfairKey, dec);
        break;
      case 'hill':
        output = hillCipher(input, state.hillMatrix, state.hillSize, dec);
        break;
      case 'scytale':
        output = dec ? scytaleDecrypt(input, state.scytaleRows)
                     : scytaleEncrypt(input, state.scytaleRows);
        break;
      case 'columnar':
        output = dec ? columnarDecrypt(input, state.columnarKey)
                     : columnarEncrypt(input, state.columnarKey);
        break;
    }
  } catch (e) {
    errMsg = e.message;
  }

  document.getElementById('output-text').value = output;
  const errEl = document.getElementById('error-msg');
  if (errMsg) { errEl.textContent = '⚠ ' + errMsg; errEl.classList.add('visible'); }
  else errEl.classList.remove('visible');

  // Perbarui penghitung karakter di header
  document.getElementById('char-count').textContent = `${input.length} chars`;
  // Perbarui semua panel analisis
  updateFrequency(output);
  updateIoC(output);
  updateWordPatterns(output);
  // Bangun ulang langkah visualisasi
  buildVizSteps();
}

/* ----------------------------------------------------------------
   5. RENDER ALGORITHM SELECTOR
   ---------------------------------------------------------------- */
function renderAlgoSelector() {
  const grid = document.getElementById('algo-grid');
  grid.innerHTML = '';
  for (const a of ALGORITHMS) {
    const btn = document.createElement('button');
    btn.className = 'algo-btn' + (a.id === state.algo ? ' active' : '');
    btn.dataset.algo = a.id;
    btn.innerHTML = `
      <div class="algo-icon">${a.icon}</div>
      <div class="algo-name">${a.name}</div>
      <div class="algo-type"><span class="badge ${a.badge}">${a.type}</span></div>
    `;
    btn.onclick = () => selectAlgo(a.id);
    grid.appendChild(btn);
  }
}

/** Pilih algoritma baru: update state, re-render panel kunci & info */
function selectAlgo(id) {
  state.algo = id;
  renderAlgoSelector();
  renderKeyCtrl();
  updateAlgoInfo();
  processText();
  const meta = ALGORITHMS.find(a => a.id === id);
  document.getElementById('algo-badge-ws').textContent = meta.name;
  document.getElementById('viz-algo-badge').textContent = meta.name;
}

/** Perbarui kartu info algoritma di panel kiri */
function updateAlgoInfo() {
  const meta = ALGORITHMS.find(a => a.id === state.algo);
  document.getElementById('algo-info-title').textContent = meta.name;
  document.getElementById('algo-info-desc').textContent = meta.desc;
  const tags = document.getElementById('algo-info-tags');
  tags.innerHTML = meta.tags.map(t => `<span class="badge ${meta.badge}">${t}</span>`).join('');
}

/* ----------------------------------------------------------------
   6. RENDER KEY CONTROLLER
   Tiap algoritma punya kontrol kunci yang berbeda.
   ---------------------------------------------------------------- */
function renderKeyCtrl() {
  const panel = document.getElementById('key-ctrl');
  panel.innerHTML = '';

  switch (state.algo) {
    case 'caesar': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Shift (1–25)</label>
          <div class="slider-wrap">
            <input type="range" id="caesar-slider" min="1" max="25" value="${state.caesarShift}"
              oninput="state.caesarShift=+this.value; document.getElementById('caesar-val').textContent=this.value; processText();" />
            <div class="slider-val" id="caesar-val">${state.caesarShift}</div>
          </div>
        </div>`;
      break;
    }
    case 'rail': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Number of Rails (2–8)</label>
          <div class="slider-wrap">
            <input type="range" id="rail-slider" min="2" max="8" value="${state.railRails}"
              oninput="state.railRails=+this.value; document.getElementById('rail-val').textContent=this.value; processText();" />
            <div class="slider-val" id="rail-val">${state.railRails}</div>
          </div>
        </div>`;
      break;
    }
    case 'vigenere': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Keyword</label>
          <input class="key-input" id="vig-key-input" type="text" value="${state.vigenereKey}"
            maxlength="30" placeholder="e.g. SECRET"
            oninput="state.vigenereKey=this.value.toUpperCase().replace(/[^A-Z]/g,''); processText();" />
        </div>`;
      break;
    }
    case 'mono': {
      // Tabel pemetaan 26 huruf
      const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      let html = `<div class="key-row"><label class="key-label">Substitution Map (Plain → Cipher)</label></div>
        <div class="mono-table" id="mono-table">`;
      for (const ch of alpha) {
        html += `<div class="mono-cell-wrap">
          <div class="mono-plain">${ch}</div>
          <input class="mono-sub" maxlength="1" value="${state.monoSubMap[ch] || ''}"
            data-plain="${ch}"
            oninput="updateMonoSub(this)" />
        </div>`;
      }
      html += '</div>';
      panel.innerHTML = html;
      break;
    }
    case 'playfair': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Keyword</label>
          <input class="key-input" id="pf-key-input" type="text" value="${state.playfairKey}"
            maxlength="25" placeholder="e.g. MONARCHY"
            oninput="state.playfairKey=this.value.toUpperCase().replace(/[^A-Z]/g,''); renderPlayfairPreview(); processText();" />
        </div>
        <div class="key-row" style="margin-top:6px;">
          <label class="key-label">Generated 5×5 Square</label>
          <div id="pf-preview" style="overflow-x:auto;"></div>
        </div>`;
      renderPlayfairPreview();
      break;
    }
    case 'hill': {
      const s = state.hillSize;
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Matrix Size</label>
          <div style="display:flex; gap:8px;">
            <button class="viz-btn ${s===2?'active':''}" style="${s===2?'border-color:var(--accent3);color:var(--accent3);':''}"
              onclick="setHillSize(2)">2×2</button>
            <button class="viz-btn ${s===3?'active':''}" style="${s===3?'border-color:var(--accent3);color:var(--accent3);':''}"
              onclick="setHillSize(3)">3×3</button>
          </div>
        </div>
        <div class="key-row">
          <label class="key-label">Key Matrix (mod 26)</label>
          <div id="hill-matrix-input"></div>
        </div>`;
      renderHillMatrix();
      break;
    }
    case 'scytale': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Number of Rows (2–10)</label>
          <div class="slider-wrap">
            <input type="range" id="sc-slider" min="2" max="10" value="${state.scytaleRows}"
              oninput="state.scytaleRows=+this.value; document.getElementById('sc-val').textContent=this.value; processText();" />
            <div class="slider-val" id="sc-val">${state.scytaleRows}</div>
          </div>
        </div>`;
      break;
    }
    case 'columnar': {
      panel.innerHTML = `
        <div class="key-row">
          <label class="key-label">Keyword</label>
          <input class="key-input" id="col-key-input" type="text" value="${state.columnarKey}"
            maxlength="20" placeholder="e.g. SECRET"
            oninput="state.columnarKey=this.value.toUpperCase().replace(/[^A-Z]/g,''); renderColumnarOrder(); processText();" />
        </div>
        <div class="key-row">
          <label class="key-label">Column Order</label>
          <div id="col-order-preview" style="font-family:monospace; font-size:12px; color:var(--accent3); font-weight:700;"></div>
        </div>`;
      renderColumnarOrder();
      break;
    }
  }
}

/** Update satu sel peta substitusi Monoalphabetic */
function updateMonoSub(input) {
  const plain = input.dataset.plain;
  const val = input.value.toUpperCase().replace(/[^A-Z]/g, '');
  input.value = val;
  state.monoSubMap[plain] = val || plain;
  processText();
}

/** Render preview kisi 5×5 Playfair setelah kunci berubah */
function renderPlayfairPreview() {
  const grid = buildPlayfairSquare(state.playfairKey);
  const prev = document.getElementById('pf-preview');
  if (!prev) return;
  let html = '<table class="pf-table"><tbody>';
  for (const row of grid) {
    html += '<tr>';
    for (const cell of row) html += `<td class="pf-cell">${cell}</td>`;
    html += '</tr>';
  }
  html += '</tbody></table>';
  prev.innerHTML = html;
}

/** Ganti ukuran matriks Hill dan reset ke nilai default */
function setHillSize(s) {
  state.hillSize = s;
  if (s === 2) state.hillMatrix = [[3,3],[2,5]];
  else state.hillMatrix = [[6,24,1],[13,16,10],[20,17,15]];
  renderKeyCtrl();
  processText();
}

/** Render grid input matriks Hill */
function renderHillMatrix() {
  const wrap = document.getElementById('hill-matrix-input');
  if (!wrap) return;
  const s = state.hillSize;
  let html = `<div class="matrix-grid" style="grid-template-columns:repeat(${s},1fr); max-width:${s*58}px;">`;
  for (let r = 0; r < s; r++) {
    for (let c = 0; c < s; c++) {
      html += `<input class="matrix-cell" type="number" min="0" max="25"
        value="${state.hillMatrix[r][c]}"
        data-r="${r}" data-c="${c}"
        oninput="updateHillCell(this)" />`;
    }
  }
  html += '</div>';
  wrap.innerHTML = html;
}

/** Update satu sel matriks Hill */
function updateHillCell(input) {
  const r = +input.dataset.r, c = +input.dataset.c;
  state.hillMatrix[r][c] = +input.value || 0;
  processText();
}

/** Tampilkan urutan pembacaan kolom Columnar berdasarkan kunci */
function renderColumnarOrder() {
  const prev = document.getElementById('col-order-preview');
  if (!prev) return;
  const k = state.columnarKey;
  const order = [...k].map((ch, i) => [ch, i])
    .sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)
    .map(([, i]) => i);
  prev.textContent = `[${order.join(' → ')}]  (column read order)`;
}

/* ----------------------------------------------------------------
   7. MODE BUTTON (Encrypt ↔ Decrypt)
   Dipanggil oleh onclick="toggleMode()" di tombol tengah workspace.
   ---------------------------------------------------------------- */
function toggleMode() {
  state.mode = state.mode === 'encrypt' ? 'decrypt' : 'encrypt';
  const isDecrypt = state.mode === 'decrypt';

  // Perbarui tampilan tombol di workspace
  const btn  = document.getElementById('mode-btn');
  const icon = document.getElementById('mode-btn-icon');
  btn.classList.toggle('decrypt', isDecrypt);
  icon.textContent = isDecrypt ? '🔓' : '🔒';

  // Perbarui badge di header
  const badge = document.getElementById('mode-header-badge');
  if (isDecrypt) {
    badge.textContent = 'DECRYPT MODE';
    badge.style.color = '#ec4899';
    badge.style.borderColor = '#fbcfe8';
    badge.style.background = 'linear-gradient(135deg,#fdf2f8,#fff0f8)';
  } else {
    badge.textContent = 'ENCRYPT MODE';
    badge.style.color = '#f59e0b';
    badge.style.borderColor = '#fde68a';
    badge.style.background = 'linear-gradient(135deg,#fffbeb,#fef9ec)';
  }

  processText();
}

/* ----------------------------------------------------------------
   8. WORKSPACE HELPERS
   ---------------------------------------------------------------- */

/** Bersihkan input dan output */
function clearInput() {
  document.getElementById('input-text').value = '';
  document.getElementById('output-text').value = '';
  document.getElementById('char-count').textContent = '0 chars';
  updateFrequency(''); updateIoC(''); updateWordPatterns('');
  buildVizSteps();
}

/** Salin output ke clipboard */
function copyOutput() {
  const out = document.getElementById('output-text').value;
  navigator.clipboard.writeText(out).catch(() => {});
}

/** Pindahkan output ke input (untuk proses berantai) */
function swapTexts() {
  const inp = document.getElementById('input-text');
  const out = document.getElementById('output-text');
  inp.value = out.value;
  processText();
}

/** Contoh teks per algoritma untuk tombol "Sample" */
const SAMPLES = {
  caesar:   'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG',
  rail:     'WEAREDISCOVEREDFLEEATONCE',
  vigenere: 'ATTACK AT DAWN',
  mono:     'HELLO WORLD',
  playfair: 'HIDE THE GOLD IN THE TREE STUMP',
  hill:     'ACT',
  scytale:  'HELPMEIAMUNDERCOVERORAGENT',
  columnar: 'WEAREDISCOVEREDFLEEATONCE',
};
function sampleText() {
  document.getElementById('input-text').value = SAMPLES[state.algo] || 'HELLO WORLD';
  processText();
}

/* ----------------------------------------------------------------
   9. CRYPTANALYSIS HELPERS
   ---------------------------------------------------------------- */

/** Frekuensi huruf bahasa Inggris (persen) — sebagai referensi */
const EN_FREQ = {
  A:8.167,B:1.492,C:2.782,D:4.253,E:12.702,F:2.228,G:2.015,H:6.094,
  I:6.966,J:0.153,K:0.772,L:4.025,M:2.406,N:6.749,O:7.507,P:1.929,
  Q:0.095,R:5.987,S:6.327,T:9.056,U:2.758,V:0.978,W:2.360,X:0.150,
  Y:1.974,Z:0.074
};

/** Hitung frekuensi kemunculan tiap huruf dalam teks (persen) */
function getFrequency(text) {
  const counts = {};
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  for (const ch of alpha) counts[ch] = 0;
  let total = 0;
  for (const ch of text.toUpperCase()) {
    if (ch >= 'A' && ch <= 'Z') { counts[ch]++; total++; }
  }
  if (total > 0) for (const ch of alpha) counts[ch] = (counts[ch] / total) * 100;
  return counts;
}

/** Render grafik batang frekuensi huruf di panel Cryptanalysis */
function updateFrequency(text) {
  const freq = getFrequency(text);
  const chart = document.getElementById('freq-chart');
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  // Urutkan dari frekuensi tertinggi
  const sorted = [...alpha].sort((a, b) => freq[b] - freq[a]);
  const maxFreq = Math.max(...Object.values(freq), 13);
  chart.innerHTML = sorted.map(ch => `
    <div class="freq-row">
      <div class="freq-letter">${ch}</div>
      <div class="freq-bar-wrap">
        <div class="freq-bar" style="width:${(freq[ch]/maxFreq*100).toFixed(1)}%"></div>
      </div>
      <div class="freq-pct">${freq[ch].toFixed(1)}%</div>
      <div class="freq-pct" style="color:var(--text-light);">${EN_FREQ[ch].toFixed(1)}%</div>
    </div>`).join('');
}

/** Hitung Index of Coincidence: IoC = Σ(ni*(ni-1)) / (N*(N-1)) */
function calcIoC(text) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const n = clean.length;
  if (n < 2) return 0;
  const counts = {};
  for (const ch of clean) counts[ch] = (counts[ch] || 0) + 1;
  let sum = 0;
  for (const v of Object.values(counts)) sum += v * (v - 1);
  return sum / (n * (n - 1));
}

/** Tampilkan nilai IoC beserta interpretasinya */
function updateIoC(text) {
  const ioc = calcIoC(text);
  document.getElementById('ioc-value').textContent = ioc.toFixed(4);
  let hint = '';
  if (ioc === 0)       hint = 'No text to analyze';
  else if (ioc < 0.042) hint = '🎲 Very random — likely random noise or transposition';
  else if (ioc < 0.056) hint = '🔑 Suggests polyalphabetic cipher (Vigenère, etc.)';
  else if (ioc < 0.068) hint = '📝 Near English average — monoalphabetic substitution likely';
  else                  hint = '✅ Very close to English — may be plaintext';
  document.getElementById('ioc-hint').textContent = hint;
}

/** Konversi kata ke pola struktural, misal HELLO → 0.1.2.2.3 */
function wordToPattern(word) {
  const map = {};
  let idx = 0;
  return word.split('').map(ch => {
    if (!(ch in map)) map[ch] = idx++;
    return map[ch];
  }).join('.');
}

/** Tampilkan daftar kata beserta pola dan kemungkinan padanannya */
function updateWordPatterns(text) {
  const words = text.toUpperCase().replace(/[^A-Z ]/g, '').split(/\s+/).filter(w => w.length > 0);
  const list = document.getElementById('pattern-list');
  if (words.length === 0) {
    list.innerHTML = '<div style="font-size:12px;color:var(--text-light);padding:8px;">No words to analyze</div>';
    return;
  }
  // Pola kata Inggris umum sebagai referensi
  const COMMON_PATTERNS = {
    '0': ['A', 'I'],
    '0.1': ['AN','AS','AT','BE','BY','DO','GO','HE','IF','IN','IS','IT','ME','MY','NO','OF','ON','OR','SO','TO','UP','US','WE'],
    '0.1.2': ['ACE','AND','ARE','CAN','DID','FOR','GET','GOT','HAD','HAS','HIM','HIS','HOW','LET','MAY','NOT','NOW','OLD','OWN','PUT','RUN','SAW','SAY','SHE','THE','TWO','WAR','WAS','WAY','WHO','WHY','YOU'],
    '0.1.0.0': ['THAT','ELLS'],
    '0.1.2.3': ['HAVE','FROM','THEY','THIS','WERE','WITH'],
    '0.1.1.2': ['BEEN','FEEL','FEET','FREE','SEEM','SEEN','WEEK'],
  };
  const unique = [...new Set(words)].slice(0, 20);
  list.innerHTML = unique.map(w => {
    const pat = wordToPattern(w);
    const matches = (COMMON_PATTERNS[pat] || []).slice(0, 3);
    return `<div class="pattern-row">
      <div class="pattern-word">${w}</div>
      <div class="pattern-code">${pat}</div>
      ${matches.length ? `<div class="pattern-match">≈ ${matches.join(', ')}</div>` : ''}
    </div>`;
  }).join('');
}

/** Tampilkan tab panel Cryptanalysis yang dipilih */
function showCryptoTab(tab) {
  document.querySelectorAll('.crypto-tab').forEach((t, i) => {
    const tabs = ['freq', 'ioc', 'pattern'];
    t.classList.toggle('active', tabs[i] === tab);
  });
  document.getElementById('crypto-freq').style.display    = tab === 'freq'    ? '' : 'none';
  document.getElementById('crypto-ioc').style.display     = tab === 'ioc'     ? '' : 'none';
  document.getElementById('crypto-pattern').style.display = tab === 'pattern' ? '' : 'none';
}

/* ----------------------------------------------------------------
   10. STEP-BY-STEP VISUALIZATION
   ---------------------------------------------------------------- */

/** Bangun daftar langkah visualisasi sesuai algoritma aktif */
function buildVizSteps() {
  const raw = document.getElementById('input-text').value;
  const dec = state.mode === 'decrypt';
  state.vizSteps = [];
  state.vizCurrentStep = 0;

  switch (state.algo) {
    case 'caesar':   buildCaesarSteps(raw, state.caesarShift, dec); break;
    case 'rail':     buildRailSteps(raw, state.railRails, dec); break;
    case 'vigenere': buildVigenereSteps(raw, state.vigenereKey, dec); break;
    case 'mono':     buildMonoSteps(raw, state.monoSubMap, dec); break;
    case 'playfair': buildPlayfairSteps(raw, state.playfairKey, dec); break;
    case 'hill':     buildHillSteps(raw, state.hillMatrix, state.hillSize, dec); break;
    case 'scytale':  buildScytaleSteps(raw, state.scytaleRows, dec); break;
    case 'columnar': buildColumnarSteps(raw, state.columnarKey, dec); break;
  }

  renderVizStep();
  const total = state.vizSteps.length;
  document.getElementById('viz-step-info').textContent = `Step ${Math.min(1, total)} / ${total || 1}`;
  document.getElementById('viz-prev-btn').disabled = true;
  document.getElementById('viz-next-btn').disabled = total <= 1;
}

/** Render langkah visualisasi saat ini ke DOM */
function renderVizStep() {
  const steps = state.vizSteps;
  const i = state.vizCurrentStep;
  if (!steps.length) {
    document.getElementById('step-narrative').textContent = 'Type text and select an algorithm to visualize steps.';
    document.getElementById('viz-content').innerHTML = '';
    return;
  }
  const step = steps[i];
  document.getElementById('step-narrative').innerHTML = step.narrative;
  document.getElementById('viz-content').innerHTML = step.html;
}

function vizPrev() {
  if (state.vizCurrentStep > 0) {
    state.vizCurrentStep--;
    renderVizStep();
    updateVizBtns();
  }
}
function vizNext() {
  if (state.vizCurrentStep < state.vizSteps.length - 1) {
    state.vizCurrentStep++;
    renderVizStep();
    updateVizBtns();
  }
}
function updateVizBtns() {
  const i = state.vizCurrentStep, n = state.vizSteps.length;
  document.getElementById('viz-prev-btn').disabled = i === 0;
  document.getElementById('viz-next-btn').disabled = i >= n - 1;
  document.getElementById('viz-step-info').textContent = `Step ${i + 1} / ${n}`;
}

/** Toggle auto-play: jalankan langkah otomatis setiap 900ms */
function toggleAutoPlay() {
  const btn = document.getElementById('viz-auto-btn');
  if (state.vizAutoTimer) {
    clearInterval(state.vizAutoTimer);
    state.vizAutoTimer = null;
    btn.textContent = '▶ Auto';
  } else {
    btn.textContent = '⏹ Stop';
    state.vizAutoTimer = setInterval(() => {
      if (state.vizCurrentStep >= state.vizSteps.length - 1) {
        clearInterval(state.vizAutoTimer);
        state.vizAutoTimer = null;
        btn.textContent = '▶ Auto';
        return;
      }
      vizNext();
    }, 900);
  }
}

/* ── Caesar Visualization ── */
function buildCaesarSteps(text, shift, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (!clean) return;
  const s = decrypt ? (26 - (shift % 26)) % 26 : shift % 26;

  // Langkah 0: tampilkan roda Caesar SVG
  state.vizSteps.push({
    narrative: `<strong>Caesar Cipher</strong> — ${decrypt?'Decrypt':'Encrypt'} with shift <strong>${shift}</strong>. The outer ring (plaintext) rotates by ${s} positions relative to the inner ring (ciphertext).`,
    html: buildCaesarWheelHTML(s),
  });

  // Langkah 1+: proses karakter satu per satu
  for (let i = 0; i < Math.min(clean.length, 20); i++) {
    const ch = clean[i];
    const out = String.fromCharCode(((ch.charCodeAt(0) - 65 + s) % 26) + 65);
    const pairs = clean.slice(0, i + 1).split('').map((c, j) => {
      const o = String.fromCharCode(((c.charCodeAt(0) - 65 + s) % 26) + 65);
      const cls = j === i ? 'current' : 'done';
      return `<div class="char-pair ${cls}">
        <span class="char-top">${c}</span>
        <span class="char-arr">↓+${s}</span>
        <span class="char-bot">${o}</span>
      </div>`;
    }).join('');
    const remain = clean.slice(i + 1).split('').map(c =>
      `<div class="char-pair"><span class="char-top">${c}</span><span class="char-arr">···</span><span class="char-bot" style="color:var(--text-light);">?</span></div>`
    ).join('');
    state.vizSteps.push({
      narrative: `Letter <strong>${ch}</strong> (position ${ch.charCodeAt(0)-64}) shifted by ${s} → <strong>${out}</strong> (position ${out.charCodeAt(0)-64}).  Formula: (${ch.charCodeAt(0)-65} + ${s}) mod 26 = ${(ch.charCodeAt(0)-65+s)%26}`,
      html: `<div class="char-map">${pairs}${remain}</div>`,
    });
  }
}

/** Bangun SVG roda Caesar dengan dua cincin alfabet */
function buildCaesarWheelHTML(shift) {
  const R1 = 82, R2 = 66, CX = 90, CY = 90;
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let inner = '', outer = '';
  for (let i = 0; i < 26; i++) {
    const angle = (i / 26) * Math.PI * 2 - Math.PI / 2;
    const x1 = CX + R1 * Math.cos(angle);
    const y1 = CY + R1 * Math.sin(angle);
    const x2 = CX + R2 * Math.cos(angle + (shift / 26) * Math.PI * 2);
    const y2 = CY + R2 * Math.sin(angle + (shift / 26) * Math.PI * 2);
    outer += `<text x="${x1.toFixed(1)}" y="${y1.toFixed(1)}" text-anchor="middle" dominant-baseline="central"
      font-size="10" font-weight="700" fill="#1e1b4b" font-family="Courier New">${alpha[i]}</text>`;
    inner += `<text x="${x2.toFixed(1)}" y="${y2.toFixed(1)}" text-anchor="middle" dominant-baseline="central"
      font-size="10" font-weight="700" fill="#6366f1" font-family="Courier New">${alpha[(i + shift) % 26]}</text>`;
  }
  return `<div class="caesar-wheel-wrap">
    <div>
      <svg viewBox="0 0 180 180" width="180" height="180" style="overflow:visible;">
        <circle cx="${CX}" cy="${CY}" r="88" fill="none" stroke="#e5e7eb" stroke-width="1.5"/>
        <circle cx="${CX}" cy="${CY}" r="72" fill="none" stroke="#bfdbfe" stroke-width="1.5" stroke-dasharray="4 2"/>
        <circle cx="${CX}" cy="${CY}" r="30" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1.5"/>
        <text x="${CX}" y="${CY}" text-anchor="middle" dominant-baseline="central"
          font-size="10" font-weight="800" fill="#6366f1" font-family="sans-serif">+${shift}</text>
        ${outer}${inner}
      </svg>
      <div class="wheel-label">Plaintext (outer) → Cipher (inner)</div>
    </div>
  </div>`;
}

/* ── Rail Fence Visualization ── */
function buildRailSteps(text, rails, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (!clean || rails < 2) return;

  // Tentukan pola rail untuk tiap posisi
  const pattern = [];
  let rail = 0, dir = 1;
  for (let i = 0; i < clean.length; i++) {
    pattern.push(rail);
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }

  // Langkah 0: tampilkan seluruh grid
  state.vizSteps.push({
    narrative: `<strong>Rail Fence</strong> with <strong>${rails} rails</strong>. Text is written in a zigzag pattern across ${rails} rows.`,
    html: buildRailGridHTML(clean, pattern, rails, -1),
  });

  // Langkah per karakter
  for (let i = 0; i < Math.min(clean.length, 15); i++) {
    state.vizSteps.push({
      narrative: `Place character <strong>${clean[i]}</strong> on rail <strong>${pattern[i] + 1}</strong> (position ${i+1}).`,
      html: buildRailGridHTML(clean, pattern, rails, i),
    });
  }

  // Langkah terakhir: baca per rail
  state.vizSteps.push({
    narrative: `Now read each rail left-to-right to form the ciphertext: <strong>${railFenceEncrypt(clean, rails)}</strong>`,
    html: buildRailGridHTML(clean, pattern, rails, clean.length),
  });
}

/** Bangun HTML tabel grid Rail Fence dengan highlight */
function buildRailGridHTML(text, pattern, rails, currentIdx) {
  const cols = text.length;
  let html = '<div class="rail-grid"><table class="rail-table"><tbody>';
  for (let r = 0; r < rails; r++) {
    html += '<tr>';
    for (let c = 0; c < cols; c++) {
      const isCurrent = c === currentIdx && pattern[c] === r;
      const isDone    = c < currentIdx   && pattern[c] === r;
      const cls = isCurrent ? 'rail-cell current' : isDone ? 'rail-cell filled' : 'rail-cell';
      const ch  = (pattern[c] === r && (c <= currentIdx || currentIdx === -1)) ? text[c] : '·';
      html += `<td class="${cls}">${ch}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}

/* ── Vigenère Visualization ── */
function buildVigenereSteps(text, key, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!clean || !k) return;

  state.vizSteps.push({
    narrative: `<strong>Vigenère Cipher</strong> — Key: <strong>"${k}"</strong>. Each plaintext letter is shifted by the corresponding key letter's value.`,
    html: buildVigenereTableHTML(clean, k, -1, decrypt),
  });

  for (let i = 0; i < Math.min(clean.length, 15); i++) {
    const ki = i % k.length;
    const ks = k[ki].charCodeAt(0) - 65;
    const p  = clean[i].charCodeAt(0) - 65;
    const c  = decrypt ? ((p - ks + 26) % 26) : ((p + ks) % 26);
    const cCh = String.fromCharCode(c + 65);
    state.vizSteps.push({
      narrative: `Pos ${i+1}: <strong>${clean[i]}</strong>(${p}) ${decrypt?'−':'+'}Key <strong>${k[ki]}</strong>(${ks}) = <strong>${cCh}</strong>(${c}).  Formula: (${p} ${decrypt?'-':'+'}${ks}+26) mod 26 = ${c}`,
      html: buildVigenereTableHTML(clean, k, i, decrypt),
    });
  }
}

/** Bangun tabel Vigenère step dengan highlight baris aktif */
function buildVigenereTableHTML(text, key, currentIdx, decrypt) {
  let html = '<div style="display:flex;flex-direction:column;gap:4px;max-height:220px;overflow-y:auto;">';
  html += `<div style="display:grid;grid-template-columns:repeat(4,auto);gap:6px;align-items:center;padding:6px;background:var(--bg);border-radius:8px;border:1px solid var(--border);font-size:11px;font-weight:700;color:var(--text-muted);">
    <div>Plain</div><div>Key</div><div>${decrypt?'−':'+'}Shift</div><div>Result</div>
  </div>`;
  for (let i = 0; i < Math.min(text.length, 15); i++) {
    const ki = i % key.length;
    const ks = key[ki].charCodeAt(0) - 65;
    const p  = text[i].charCodeAt(0) - 65;
    const c  = decrypt ? ((p - ks + 26) % 26) : ((p + ks) % 26);
    const isCurrent = i === currentIdx;
    html += `<div class="vig-row${isCurrent?' current-step':''}">
      <span class="vig-plain">${text[i]}</span>
      <span style="color:var(--text-muted);">+</span>
      <span class="vig-key">${key[ki]}(${ks})</span>
      <span style="color:var(--text-muted);">=</span>
      <span class="vig-result">${i <= currentIdx || currentIdx === -1 ? String.fromCharCode(c+65) : '?'}</span>
    </div>`;
  }
  html += '</div>';
  return html;
}

/* ── Mono Visualization ── */
function buildMonoSteps(text, subMap, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (!clean) return;
  // Langkah 0: tampilkan seluruh peta substitusi
  state.vizSteps.push({
    narrative: `<strong>Monoalphabetic Substitution</strong> — Each letter is replaced by its fixed substitute from the key map.`,
    html: buildMonoMapHTML(subMap, decrypt),
  });
  // Langkah per karakter
  for (let i = 0; i < Math.min(clean.length, 20); i++) {
    const ch = clean[i];
    let out;
    if (decrypt) {
      out = Object.entries(subMap).find(([k,v]) => v === ch)?.[0] || ch;
    } else {
      out = subMap[ch] || ch;
    }
    const pairs = clean.slice(0,i+1).split('').map((c,j) => {
      let o = decrypt ? (Object.entries(subMap).find(([k,v])=>v===c)?.[0]||c) : (subMap[c]||c);
      return `<div class="char-pair ${j===i?'current':'done'}">
        <span class="char-top">${c}</span>
        <span class="char-arr">→</span>
        <span class="char-bot">${o}</span>
      </div>`;
    }).join('');
    state.vizSteps.push({
      narrative: `Letter <strong>${ch}</strong> → <strong>${out}</strong> (fixed substitution).`,
      html: `<div class="char-map">${pairs}</div>`,
    });
  }
}

/** Tampilkan seluruh alfabet beserta substitusinya */
function buildMonoMapHTML(subMap) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let html = '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
  for (const ch of alpha) {
    const sub = subMap[ch] || '?';
    html += `<div style="display:flex;flex-direction:column;align-items:center;gap:1px;padding:4px;background:var(--bg);border-radius:4px;border:1px solid var(--border);">
      <span style="font-family:monospace;font-size:11px;font-weight:700;color:var(--text-muted);">${ch}</span>
      <span style="font-size:8px;color:var(--text-light);">↓</span>
      <span style="font-family:monospace;font-size:11px;font-weight:700;color:var(--accent2);">${sub}</span>
    </div>`;
  }
  html += '</div>';
  return html;
}

/* ── Playfair Visualization ── */
function buildPlayfairSteps(text, key, decrypt) {
  const grid = buildPlayfairSquare(key);
  let clean = text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
  if (!clean) return;

  // Siapkan digraf
  const digraphs = [];
  let i = 0;
  while (i < clean.length) {
    const a = clean[i];
    const b = i+1 < clean.length ? clean[i+1] : 'X';
    if (a === b) { digraphs.push([a,'X']); i++; } else { digraphs.push([a,b]); i+=2; }
  }

  // Langkah 0: tampilkan kisi dan daftar digraf
  state.vizSteps.push({
    narrative: `<strong>Playfair Cipher</strong> — Key square built from: <strong>"${key}"</strong>. Text split into digraphs (pairs): ${digraphs.map(d=>`<strong>${d[0]}${d[1]}</strong>`).join(', ')}`,
    html: buildPlayfairGridHTML(grid, [], []),
  });

  // Langkah per digraf
  for (const [a, b] of digraphs.slice(0, 8)) {
    const [ra,ca] = findInGrid(grid, a);
    const [rb,cb] = findInGrid(grid, b);
    const d = decrypt ? -1 : 1;
    let outA, outB, rule;
    if (ra === rb) {
      outA = grid[ra][(ca+d+5)%5]; outB = grid[rb][(cb+d+5)%5];
      rule = `Same row → shift columns ${decrypt?'left':'right'}`;
    } else if (ca === cb) {
      outA = grid[(ra+d+5)%5][ca]; outB = grid[(rb+d+5)%5][cb];
      rule = `Same column → shift rows ${decrypt?'up':'down'}`;
    } else {
      outA = grid[ra][cb]; outB = grid[rb][ca];
      rule = `Rectangle → swap corners`;
    }
    state.vizSteps.push({
      narrative: `Digraph <strong>${a}${b}</strong> → <strong>${outA}${outB}</strong>. Rule: ${rule}.`,
      html: buildPlayfairGridHTML(grid, [[ra,ca],[rb,cb]], [[ra,cb],[rb,ca]]),
    });
  }
}

/** Bangun HTML tabel Playfair 5×5 dengan sel sumber & tujuan dihighlight */
function buildPlayfairGridHTML(grid, srcs, dsts) {
  const srcSet = new Set(srcs.map(([r,c])=>`${r},${c}`));
  const dstSet = new Set(dsts.map(([r,c])=>`${r},${c}`));
  let html = '<div class="playfair-grid-wrap"><table class="pf-table"><tbody>';
  for (let r = 0; r < 5; r++) {
    html += '<tr>';
    for (let c = 0; c < 5; c++) {
      const k = `${r},${c}`;
      const cls = srcSet.has(k) ? 'pf-cell highlight-src' : dstSet.has(k) ? 'pf-cell highlight-dst' : 'pf-cell';
      html += `<td class="${cls}">${grid[r][c]}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}

/* ── Hill Visualization ── */
function buildHillSteps(text, matrix, size, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g,'');
  if (!clean) return;
  let padded = clean;
  while (padded.length % size !== 0) padded += 'X';

  let mat = matrix;
  if (decrypt) {
    mat = size === 2 ? mat2x2Inv(matrix) : mat3x3Inv(matrix);
    if (!mat) { state.vizSteps.push({ narrative: 'Key matrix is not invertible mod 26.', html: '' }); return; }
  }

  // Langkah 0: tampilkan matriks kunci
  state.vizSteps.push({
    narrative: `<strong>Hill Cipher (${size}×${size})</strong> — Each block of ${size} letters is treated as a vector and multiplied by the key matrix (mod 26).`,
    html: buildHillMatrixHTML(matrix, size),
  });

  // Langkah per blok
  for (let i = 0; i < padded.length; i += size) {
    const vec = Array.from({length:size}, (_,j) => padded.charCodeAt(i+j)-65);
    const out = matMulMod(mat, vec, 26).map(n => ((n%26)+26)%26);
    state.vizSteps.push({
      narrative: `Block "${padded.slice(i,i+size)}" (${vec.join(',')}) × Matrix = (${out.join(',')}) = "<strong>${out.map(n=>String.fromCharCode(n+65)).join('')}</strong>"`,
      html: buildHillStepHTML(mat, vec, out, size),
    });
  }
}

/** Tampilkan matriks saja (langkah intro Hill) */
function buildHillMatrixHTML(mat, size) {
  let html = '<div class="hill-step" style="justify-content:center;"><div class="hill-matrix-display">';
  for (let r = 0; r < size; r++) {
    html += '<div class="hill-matrix-row">';
    for (let c = 0; c < size; c++) html += `<div class="hm-cell">${mat[r][c]}</div>`;
    html += '</div>';
  }
  html += '</div></div>';
  return html;
}

/** Tampilkan matriks × vektor = hasil (Hill per blok) */
function buildHillStepHTML(mat, vec, out, size) {
  let html = '<div class="hill-step" style="justify-content:center;align-items:center;">';
  html += '<div class="hill-matrix-display">';
  for (let r = 0; r < size; r++) {
    html += '<div class="hill-matrix-row">';
    for (let c = 0; c < size; c++) html += `<div class="hm-cell">${mat[r][c]}</div>`;
    html += '</div>';
  }
  html += '</div>';
  html += '<div style="font-size:18px;color:var(--text-muted);">×</div>';
  html += '<div class="hill-vec">';
  for (const v of vec) html += `<div class="hv-cell in">${v}</div>`;
  html += '</div>';
  html += '<div style="font-size:18px;color:var(--text-muted);">=</div>';
  html += '<div class="hill-vec">';
  for (const v of out) html += `<div class="hv-cell out">${v}</div>`;
  html += '</div>';
  html += '</div>';
  return html;
}

/* ── Scytale Visualization ── */
function buildScytaleSteps(text, rows, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g,'');
  if (!clean) return;
  const cols = Math.ceil(clean.length / rows);
  let padded = clean;
  while (padded.length < rows * cols) padded += 'X';

  // Langkah 0: tampilkan seluruh grid
  state.vizSteps.push({
    narrative: `<strong>Scytale</strong> with <strong>${rows} rows</strong> and ${cols} columns. Text is placed into a ${rows}×${cols} grid row-by-row.`,
    html: buildScytaleGridHTML(padded, rows, cols, -1),
  });

  // Langkah per kolom
  for (let c = 0; c < cols; c++) {
    state.vizSteps.push({
      narrative: `Read column <strong>${c+1}</strong> — "${Array.from({length:rows},(_,r)=>padded[r*cols+c]||'').join('')}". Columns are read top-to-bottom to form ciphertext.`,
      html: buildScytaleGridHTML(padded, rows, cols, c),
    });
  }
}

/** Bangun HTML grid Scytale dengan kolom aktif dihighlight */
function buildScytaleGridHTML(text, rows, cols, currentCol) {
  let html = '<div class="scytale-grid"><table class="scytale-table"><tbody>';
  for (let r = 0; r < rows; r++) {
    html += '<tr>';
    for (let c = 0; c < cols; c++) {
      const ch = text[r*cols+c] || '·';
      const isCurrent = c === currentCol;
      const isDone    = c < currentCol;
      const cls = isCurrent ? 'sc-cell current' : isDone ? 'sc-cell col-highlight' : 'sc-cell';
      html += `<td class="${cls}">${ch}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}

/* ── Columnar Visualization ── */
function buildColumnarSteps(text, key, decrypt) {
  const clean = text.toUpperCase().replace(/[^A-Z]/g,'');
  const k = key.toUpperCase().replace(/[^A-Z]/g,'');
  if (!clean || !k) return;
  const cols = k.length;
  const rows = Math.ceil(clean.length / cols);
  let padded = clean;
  while (padded.length < rows*cols) padded += 'X';

  const order = [...k].map((ch,i)=>[ch,i]).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0).map(([,i])=>i);

  // Langkah 0: tampilkan seluruh grid dengan header kunci
  state.vizSteps.push({
    narrative: `<strong>Columnar Transposition</strong> — Key: <strong>"${k}"</strong>. Text written into ${rows} rows of ${cols} columns. Columns are read in alphabetical order of key letters.`,
    html: buildColumnarGridHTML(padded, rows, cols, k, order, -1),
  });

  // Langkah per kolom sesuai urutan kunci
  for (let i = 0; i < order.length; i++) {
    const col = order[i];
    state.vizSteps.push({
      narrative: `Read column <strong>${col+1}</strong> (key letter <strong>"${k[col]}"</strong>, rank ${i+1} in alphabetical order): "${Array.from({length:rows},(_,r)=>padded[r*cols+col]).join('')}"`,
      html: buildColumnarGridHTML(padded, rows, cols, k, order, i),
    });
  }
}

/** Bangun HTML grid Columnar dengan kolom aktif dan yang sudah dibaca dihighlight */
function buildColumnarGridHTML(text, rows, cols, key, order, stepIdx) {
  const currentCol = stepIdx >= 0 ? order[stepIdx] : -1;
  const doneSet = new Set(stepIdx >= 0 ? order.slice(0, stepIdx) : []);

  let html = '<div class="col-grid-wrap"><table class="col-table"><thead><tr>';
  for (let c = 0; c < cols; c++) html += `<th class="col-header-cell">${key[c]}</th>`;
  html += '</tr></thead><tbody>';
  for (let r = 0; r < rows; r++) {
    html += '<tr>';
    for (let c = 0; c < cols; c++) {
      const ch = text[r*cols+c] || '·';
      const isCurrent = c === currentCol;
      const isDone    = doneSet.has(c);
      const cls = isCurrent ? 'col-cell current' : isDone ? 'col-cell highlight' : 'col-cell';
      html += `<td class="${cls}">${ch}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}

/* ----------------------------------------------------------------
   11. INIT & LIVE UPDATE
   ---------------------------------------------------------------- */

/** Inisialisasi aplikasi saat DOM siap */
function init() {
  renderAlgoSelector();
  renderKeyCtrl();
  updateAlgoInfo();
  updateFrequency('');
  updateIoC('');
  updateWordPatterns('');
  buildVizSteps();
}

// Proses ulang setiap kali pengguna mengetik di textarea input
document.getElementById('input-text').addEventListener('input', () => {
  processText();
});

init();
