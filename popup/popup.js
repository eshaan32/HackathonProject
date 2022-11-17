// 'https://api.pwnedpasswords.com/range/cbfda'.concat(firstDigits)

// const firstDigits = cbfda
// const lastDigits = c6008f9cab4083784cbd1874f76618d2a97

async function makeGetRequest(url) {
  const response = await fetch(url);
  // return await response.json();
  return await response.text();
}

async function generateData(url) {
  const scheduleData = await makeGetRequest(url);
  //   console.log(scheduleData);
  //   console.log(typeof scheduleData)

  return scheduleData;
}

// Function to create the URL to pass into get request
function generateUrl(firstFive) {
  return `https://api.pwnedpasswords.com/range/${firstFive}`;
}

async function parseData(password) {
  const shaadPassword = SHA1(password).toUpperCase();
  const firstFive = shaadPassword.slice(0, 5);
  const lastDigits = shaadPassword.slice(5);

  const url = generateUrl(firstFive);
  const data = await generateData(url);
  const dataArr = data.split(/\r?\n/);
  // console.log(dataArr);
  // console.log(typeof dataArr);
  // console.log(parseLine(dataArr[0]))

  // const shadPassword = SHA1('password123').toUpperCase().slice(5)
  console.log(lastDigits);
  // logic here
  let count = 0;
  dataArr.forEach((el) => {
    const parsedEl = parseLine(el);
    const [str, num] = parsedEl;
    console.log([str, num]);
    // if the hash
    if (str === lastDigits) count += num;
  });
  return count;
}

// Do logic and get our number
document
  .querySelector('.pwd-submit-btn')
  .addEventListener('click', async function () {
    const password = document.getElementById('password').value;

    document.querySelector('.pwned-count').innerHTML = await parseData(
      password
    );

    // get background element
    // check if value at pwned-count is greater than 0
    if (Number(document.querySelector('.pwned-count').textContent) > 0) {
      document.querySelector('.our-body').style.backgroundImage =
        "url('/images/scaryBackground2.png')";

      // if so, change background color to red
      // else change to green
    } else {
      document.querySelector('.our-body').style.backgroundImage =
        "url('/images/defaultBackground.png')";
    }
  });

//function that takes a hashcode from the parsed get request and turns into an array that outputs the sha1 and the num of breaches for that sha1 in an array
function parseLine(str) {
  const result = str.split(':');
  result[1] = Number(result[1]);
  return result;
}

// https://api.pwnedpasswords.com/range/cbfda
// SHA1 hash generator
function SHA1(msg) {
  function rotate_left(n, s) {
    var t4 = (n << s) | (n >>> (32 - s));
    return t4;
  }
  function lsb_hex(val) {
    var str = '';
    var i;
    var vh;
    var vl;
    for (i = 0; i <= 6; i += 2) {
      vh = (val >>> (i * 4 + 4)) & 0x0f;
      vl = (val >>> (i * 4)) & 0x0f;
      str += vh.toString(16) + vl.toString(16);
    }
    return str;
  }
  function cvt_hex(val) {
    var str = '';
    var i;
    var v;
    for (i = 7; i >= 0; i--) {
      v = (val >>> (i * 4)) & 0x0f;
      str += v.toString(16);
    }
    return str;
  }
  function Utf8Encode(string) {
    string = string.replace(/\r\n/g, '\n');
    var utftext = '';
    for (var n = 0; n < string.length; n++) {
      var c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if (c > 127 && c < 2048) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }
  var blockstart;
  var i, j;
  var W = new Array(80);
  var H0 = 0x67452301;
  var H1 = 0xefcdab89;
  var H2 = 0x98badcfe;
  var H3 = 0x10325476;
  var H4 = 0xc3d2e1f0;
  var A, B, C, D, E;
  var temp;
  msg = Utf8Encode(msg);
  var msg_len = msg.length;
  var word_array = new Array();
  for (i = 0; i < msg_len - 3; i += 4) {
    j =
      (msg.charCodeAt(i) << 24) |
      (msg.charCodeAt(i + 1) << 16) |
      (msg.charCodeAt(i + 2) << 8) |
      msg.charCodeAt(i + 3);
    word_array.push(j);
  }
  switch (msg_len % 4) {
    case 0:
      i = 0x080000000;
      break;
    case 1:
      i = (msg.charCodeAt(msg_len - 1) << 24) | 0x0800000;
      break;
    case 2:
      i =
        (msg.charCodeAt(msg_len - 2) << 24) |
        (msg.charCodeAt(msg_len - 1) << 16) |
        0x08000;
      break;
    case 3:
      i =
        (msg.charCodeAt(msg_len - 3) << 24) |
        (msg.charCodeAt(msg_len - 2) << 16) |
        (msg.charCodeAt(msg_len - 1) << 8) |
        0x80;
      break;
  }
  word_array.push(i);
  while (word_array.length % 16 != 14) word_array.push(0);
  word_array.push(msg_len >>> 29);
  word_array.push((msg_len << 3) & 0x0ffffffff);
  for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
    for (i = 0; i < 16; i++) W[i] = word_array[blockstart + i];
    for (i = 16; i <= 79; i++)
      W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;
    for (i = 0; i <= 19; i++) {
      temp =
        (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5a827999) &
        0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }
    for (i = 20; i <= 39; i++) {
      temp =
        (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ed9eba1) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }
    for (i = 40; i <= 59; i++) {
      temp =
        (rotate_left(A, 5) +
          ((B & C) | (B & D) | (C & D)) +
          E +
          W[i] +
          0x8f1bbcdc) &
        0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }
    for (i = 60; i <= 79; i++) {
      temp =
        (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xca62c1d6) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotate_left(B, 30);
      B = A;
      A = temp;
    }
    H0 = (H0 + A) & 0x0ffffffff;
    H1 = (H1 + B) & 0x0ffffffff;
    H2 = (H2 + C) & 0x0ffffffff;
    H3 = (H3 + D) & 0x0ffffffff;
    H4 = (H4 + E) & 0x0ffffffff;
  }
  var temp =
    cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);

  return temp.toLowerCase();
}
