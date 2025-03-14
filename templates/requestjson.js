    ////////////////////////////////////////////////////////////////
    //                                                            //
    //           Cripto::DB-256::S'Sums  Client Signer            //
    //                                                            //
    ////////////////////////////////////////////////////////////////


    /*
    * Software Name: CryptoDbSS
    * Copyright (C) 2025 Steeven J Salazar.
    * License: CryptoDbSS: Software Review and Audit License
    * 
    * https://github.com/Steeven512/CryptoDbSS
    *
    * IMPORTANT: Before using, compiling or do anything with this software, 
    * you must read and accept the terms of this License.
    * 
    * This software is provided "as is," without warranty of any kind.
    * For more details, see the LICENSE file.
    */

var serverurl = window.location.origin;

function HexCheck(derHexString) {
  for (let i = 0; i < derHexString.length; i++) {
    if (!isHexDigit(derHexString[i])) {
            return false;
    }
  }
  return true
}

function ullToHex(ullValue) {
  let hex = ullValue.toString(16);
  while (hex.length < 16) {
    hex = "0" + hex;
  }
  return hex;
}

async function clicsearch() {

  var form2 = document.getElementById("myForm").elements[0].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch(serverurl+"/balance", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "resource": form2, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));

}

async function MakeWallet() {

  var form2 = document.getElementById("myForm").elements[0].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch(serverurl+"/MakeWallet", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "resource": form2, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));
}

async function balance() {


  var form2 = document.getElementById("myForm").elements[0].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch(serverurl+"/balance", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "resource": form2, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = parseInt(Number("0x"+data), 10))
.catch(error => console.log(error));

}

async function transfer() {

  var w= document.getElementById("myForm").elements[0].value;
  var x = document.getElementById("myForm").elements[1].value;
  var y = document.getElementById("myForm").elements[2].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch("https://0.0.0.0:18090/transac", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "w": w, "x": x, "y": y })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));

}

async function blocksearch() {


  var form2 = document.getElementById("myForm").elements[0].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch(serverurl+"/blocksearch", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "resource": form2, "b": 2 })
})
.then(response => response.text())
.then(data => {
  let porcion1 = data.substring(0, 64); // extraer los primeros 10 caracteres
  let porcion2 = data.substring(10, 20); // extraer los siguientes 10 caracteres
  let porcion3 = data.slice(20); // extraer el resto de la cadena

  // asignar cada porción a un contenedor HTML
  document.getElementById("response").innerHTML = data;
 
})
.catch(error => console.log(error));

}

async function DataTransacIndex(typeIndex) {

  var typeIndex = ullToHex(parseInt(typeIndex, 10)).toUpperCase();
  var form1 = ullToHex(parseInt(document.getElementById("blnumber").value, 10)).toUpperCase();
  var form2 = ullToHex(parseInt(document.getElementById("transacNumber").value, 10)).toUpperCase();
  var form3= document.getElementById("transachash").value;

  document.getElementById("response").innerHTML = "buscando";
  console.log("debug form3 "+form3)

  fetch(serverurl+"/IndexTransaction", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "typeIndex": typeIndex, "valueA": form1, "valueB": form2, "valueC": form3 })
})
.then(response => response.text())
.then(data => {
  let porcion1 = data.substring(0, 64); // extraer los primeros 10 caracteres
  let porcion2 = data.substring(10, 20); // extraer los siguientes 10 caracteres
  let porcion3 = data.slice(20); // extraer el resto de la cadena

  // asignar cada porción a un contenedor HTML
  document.getElementById("response").innerHTML = data;
 
})
.catch(error => console.log(error));

}

setInterval(function() {
  fetch(serverurl + '/status', {
    method: 'GET'
  })
  .then(function(response) {
    if (response.ok) {
      return response.json(); // Analiza la respuesta como JSON
    } else {
      throw new Error('Error en la solicitud');
    }
  })
  .then(function(jsonArray) {
    jsonArray.forEach(function(elemento) {

      const elementIds = ["sync", "lastOpConfirmed", "blksize" ,"lastblblocal" , "lstblnetwork" , "ShaLBB"]; // Mapeo entre los índices del JSON array y los IDs de los elementos HTML

      // Iterar por cada elemento del JSON array
      jsonArray.forEach(function(elemento, indice) {
        const elementId = elementIds[indice]; // Obtener el ID correspondiente al índice
        
        const myElement = document.getElementById(elementId); // Seleccionar el elemento HTML por su ID
        
        if (myElement) {
          myElement.innerHTML = elemento; 
          if( elemento == "synced" ){
            const circleElement = document.querySelector('.circle'); // Seleccionar el elemento con la clase 'circle'

            circleElement.style.backgroundColor = "rgb(52, 137, 222)"; // Cambiar el color de fondo a rojo
          }

          if( elemento == "syncing..." ){
            const circleElement = document.querySelector('.circle'); // Seleccionar el elemento con la clase 'circle'

            circleElement.style.backgroundColor = "rgb(228, 102, 34)"; // Cambiar el color de fondo a rojo
          }
        }
      });


      // Realiza cualquier otra operación con cada elemento aquí
    });
  })
  .catch(function(error) {
    console.log('Error:', error);
  });
}, 15000);

async function blks(x) {

  var form2 = document.getElementById("myForm").elements[0].value;
  document.getElementById("response").innerHTML = "buscando";

  fetch(serverurl+"/blks", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "x": x, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));
}

// Función para cifrar un texto utilizando una clave AES
async function encryptText(text, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  const iv = window.crypto.getRandomValues(new Uint8Array(16));

  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: iv
    },
    key,
    data
  );

  const encryptedBytes = new Uint8Array(encryptedData);
  const encryptedHex = Array.prototype.map
    .call(encryptedBytes, byte => ("00" + byte.toString(16)).slice(-2))
    .join("");

  const ivHex = Array.prototype.map
    .call(iv, byte => ("00" + byte.toString(16)).slice(-2))
    .join("");

  return ivHex + encryptedHex;
}

// Función para descifrar un texto cifrado utilizando una clave AES
async function decryptText(ciphertext, key) {
  const iv = ciphertext.slice(0, 32);
  const encryptedDataHex = ciphertext.slice(32);

  const encryptedBytes = new Uint8Array(
    encryptedDataHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
  );

  const decryptedData = await window.crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
    },
    key,
    encryptedBytes
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}

async function calculateSHA3Hash(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(byte => ("00" + byte.toString(16)).slice(-2)).join("");

  return hashHex;
}

async function calculateSHA3HashDeriva(){
  ToSha = document.getElementById("ToSha").value
  console.log(" the string to sha is "+ ToSha)
  sha256 = await calculateSHA3Hash(ToSha)
  console.log(" the sha is "+ sha256)
  document.getElementById("response").innerHTML = sha256
}

function hexStringToUint8Array(hexString) {
  const hexArray = hexString.match(/.{1,2}/g);
  return new Uint8Array(hexArray.map(byte => parseInt(byte, 16)));
}

document.addEventListener('DOMContentLoaded', function() {
  var popup = document.getElementById('popup');
  var checkbox = document.getElementById('checkbox');
  var isChecked = getCookie('checkboxValue');

  if (isChecked !== 'true') {
    popup.style.display = 'block';
    checkbox.checked = false;
  } else {
    popup.style.display = 'none';
    checkbox.checked = true;
  }
});

document.getElementById('cerrarBtn').addEventListener('click', function() {
  var popup = document.getElementById('popup');
  var checkbox = document.getElementById('checkbox');
  popup.style.display = 'none';

  // Guarda el estado del cuadro de selección en una cookie
  setCookie('checkboxValue', checkbox.checked ? 'true' : 'false');
});

// Función para obtener el valor de una cookie
function getCookie(name) {
  var cookieName = name + '=';
  var decodedCookie = decodeURIComponent(document.cookie);
  var cookieArray = decodedCookie.split(';');
  for (var i = 0; i < cookieArray.length; i++) {
    var cookie = cookieArray[i];
    while (cookie.charAt(0) === ' ') {
      cookie = cookie.substring(1);
    }
    if (cookie.indexOf(cookieName) === 0) {
      return cookie.substring(cookieName.length, cookie.length);
    }
  }
  return '';
}

// Función para establecer el valor de una cookie
function setCookie(name, value) {
  var expirationDate = new Date();
  expirationDate.setTime(expirationDate.getTime() + (365 * 24 * 60 * 60 * 1000)); // Caduca en 1 año
  var cookieValue = encodeURIComponent(value) + '; expires=' + expirationDate.toUTCString() + '; path=/';
  document.cookie = name + '=' + cookieValue;
}