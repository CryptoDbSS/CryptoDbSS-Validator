    ////////////////////////////////////////////////////////////////
    //                                                            //
    //           Cripto::DB-256::S'Sums  Node admin panel         //
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

async function queue(x1,x2) {

  fetch(serverurl+"/queue", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "x1": x1, "x2": x2 })
})
.then(response => {
  if (response.ok) {
    return response.text(); // Convertir la respuesta a texto
  } else {
    throw new Error('Error en la solicitud');
  }
})
.then(json_data => {

  var data = JSON.parse(json_data);

  console.log(json_data);
  console.log(data);
  // Una vez que obtengas los datos del servidor Crow, puedes agregar las opciones al elemento select
 // data.forEach(function (element) {
   // const optionElement = document.createElement('option');
   // optionElement.value = element;
  //  optionElement.textContent = element;
   // selectElement.appendChild(optionElement);
  });
}

async function handleButtonClick(name) {

          console.log("debug")
          // Actualiza el contenido del párrafo en el modal
          document.getElementById('exampleModalLabel').innerText = name;
          // Muestra el modal
          var modal = new bootstrap.Modal(document.getElementById('exampleModal'));
          modal.show();

}

function clearTable() {
  const table = document.getElementById('my-table');
  const tableBody = document.getElementById('table-body');
  tableBody.innerHTML = ''; // delete tbody content
  table.appendChild(tableBody); // add again tbody emty in the table
}

function createTableRow(rowIndex, firstCell, secondCell, thirdCell) {
  const tr = document.createElement('tr');

  const th1 = document.createElement('th');
  th1.textContent = firstCell;
  tr.appendChild(th1);

  const th2 = document.createElement('th');
  th2.textContent = secondCell;
  tr.appendChild(th2);

  const th3 = document.createElement('th');
  th3.textContent = thirdCell;
  tr.appendChild(th3);

  //if(rowIndex > 0 ){
    const buttonCell = document.createElement('th');
    const button = document.createElement('button');
    button.textContent = 'edit settings';
    button.addEventListener('click', () => handleButtonClick(firstCell));
    buttonCell.appendChild(button);
    tr.appendChild(buttonCell);
  //}

  const tableBody = document.getElementById('table-body');
  tableBody.appendChild(tr);
}

async function loadtable(araytable){
  clearTable()
  for (let i = 0; i < araytable.length/4 ; i++) {
    const rowIndex = araytable[i * 4];
    const firstCell = araytable[i * 4 + 1];
    const secondCell = araytable[i * 4 + 2];
    const thirdCell = araytable[i * 4 + 3];
    createTableRow(rowIndex, firstCell, secondCell, thirdCell);
  }
}

async function AuthQueryA(queryserver){

  console.log(" AuthQueryA init ")
  getKey()
  var date = Math.floor(Date.now() / 1000)
  var msg =  apiKey+ullToHex(date)+queryserver
  var signature =  singAndCheck(localStorage.getItem('authCryptoToken'), msg )

  console.log(" cryptokey read debug ", localStorage.getItem('authCryptoToken'))
  console.log(" cryptokey public derived debug ", derive(localStorage.getItem('authCryptoToken') ))
  console.log("AuthQuery apiKeySession debug ", apiKey)

  try {
      const response = await fetch(`${serverurl}/ApiReq`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
      body: JSON.stringify({ "o":  "AuthQueryA", "arg1": msg, "arg2": signature})
      })

      var data = await response.json()
      console.log("AuthQuery response ", data)
      if(data ===  "SESSION_EXPIRED"){
        localStorage.removeItem('authToken')
        redirectWithGet(serverurl+"/index", "") 
      }
        return data
        
  }  catch (error) {
          console.log("error ",error);
  }

return "error"

}

async function NodesDir() {

try {
  const response = await fetch(`${serverurl}/NodesDir`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
  })

  var data = await response.json()
  console.log(data)
  await loadtable(data)
    
}  catch (error) {
      console.log("error ",error);
}

}

async function peers() {

    var form2 = document.getElementById("myForm").elements[0].value;
    document.getElementById("response").innerHTML = "buscando";
  
    fetch(serverurl+"/GetPeers", {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": ".", "b": 2 })
  })
  .then(response => response.text())
  .then(data => document.getElementById("response").innerHTML = data)
  .catch(error => console.log(error));
}
  
async function paire() {
  
    var ip = document.getElementById("ip").value;

    var selectElement = document.getElementById('exampleModalLabel');
    var publicPair = selectElement.value;
  
    document.getElementById("response").innerHTML = "buscando";

    console.log(publicPair)
  
    fetch(serverurl+"/paire", {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({"ip": ip, "PublicAddress": publicPair })
  })
  .then(response => response.text())
  .then(data => document.getElementById("response").innerHTML = data)
  .catch(error => console.log(error));
}

async function NodesNetworkSet(x) {

  var ip = ""
  var publicPair = ""
  ip = document.getElementById("ip").value;
  publicPair = document.getElementById('exampleModalLabel').innerText
  console.log("ip to req ",ip)
  document.getElementById("response").innerHTML = "req";
  fetch(serverurl+"/NodesNetworkSet", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({"x1": x, "x2": publicPair, "x3": ip })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data
)
.catch(error => console.log(error));
}
  
async function AddPublic() {
  
    var publicPair = document.getElementById("PublicNodeDir").elements[0].value;
  
    document.getElementById("response").innerHTML = "buscando";
  
    fetch(serverurl+"/NodesNetworkSet", {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({"x1": "SaveNode", "x2": publicPair})
  })
  .then(response => response.text())
  .then(data => document.getElementById("response").innerHTML = data)
  .catch(error => console.log(error));
}

async function peerslist() {
    // Obtén una referencia al elemento select en el DOM
    document.getElementById("response").innerHTML = "Index Files";
    
    // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
    // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
    fetch(serverurl+'/peerslist')
    .then(response => {
      if (response.ok) {
        return response.text(); // Convertir la respuesta a texto
      } else {throw new Error('Error en la solicitud');
      }
    })
    .then(json_data => {
  
      var data = JSON.parse(json_data);
  // Iterar sobre los elementos del vector y construir la celda de 2 columnas
      console.log(json_data);
      console.log(data);
      var table = document.createElement("table");
      data.forEach(function (element) {
          var row = document.createElement("tr");
          var column1 = document.createElement("td");
          var column2 = document.createElement("td");
          column1.textContent = element[0]; // Primer elemento del array (string)
          column2.innerHTML = `<button type="button" class="btn btn-dark" onclick="download('${element}')">Descargar ${element}</button>`;
          row.appendChild(column1);
          row.appendChild(column2);
          table.appendChild(row);
        });
  
  // Agregar la tabla al elemento HTML donde deseas mostrarla
  var container = document.getElementById("response");
  container.appendChild(table);
      
    })
    .catch(error => {
      // Manejo de errores en caso de que la solicitud falle
      console.log('Error:', error);
    });
    
}

async function refact() {

  fetch(serverurl+"/Refact", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "resource": 1, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));

}

async function accIndexing(acc) {

  fetch(serverurl+"/accIndexing", {
    method: 'POST',
    headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ "x": acc, "b": 2 })
})
.then(response => response.text())
.then(data => document.getElementById("response").innerHTML = data)
.catch(error => console.log(error));

}

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

function dropDown(event) {
  event.target.parentElement.children[1].classList.remove("d-none");
  document.getElementById("overlay").classList.remove("d-none");
}

function hide(event) {
  var items = document.getElementsByClassName('menu');
  for (let i = 0; i < items.length; i++) {
      items[i].classList.add("d-none");
  }
  document.getElementById("overlay").classList.add("d-none");
}

async function setmaxtr() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('maxblqtty').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 1 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

async function maxsecresp() {
    // Obtén una referencia al elemento select en el DOM
    const selectElement = document.getElementById('maxsecresp').value;
    console.log(selectElement)
    
    // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
    // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
    fetch(serverurl+'/SetAdm', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ "resource": selectElement, "o": 2 })
         }).then(response => response.text())
         .then(data => document.getElementById("response").innerHTML = data)
         .catch(error => console.log(error));
}

async function portset() {
      // Obtén una referencia al elemento select en el DOM
      const selectElement = document.getElementById('portset').value;
      console.log(selectElement)
      
      // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
      // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
      fetch(serverurl+'/SetAdm', {
          method: 'POST',
          headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json'
          },
          body: JSON.stringify({ "resource": selectElement, "o": 3 })
           }).then(response => response.text())
           .then(data => document.getElementById("response").innerHTML = data)
           .catch(error => console.log(error));
}

async function feedsToDirset() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('feedsToDirset').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 4 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

async function feedsRatioset() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('feedsRatioset').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 5 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

async function shablbmaxbuffer() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('shablbmaxbuffer').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 6 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

async function accIndexMaxCache() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('accIndexMaxCache').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 7 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

async function SetTimingBl() {
  // Obtén una referencia al elemento select en el DOM
  const selectElement = document.getElementById('SetTimingBl').value;
  console.log(selectElement)
  
  // Realiza una solicitud al servidor Crow para obtener las opciones disponibles
  // Puedes utilizar cualquier método de solicitud, como fetch o XMLHttpRequest
  fetch(serverurl+'/SetAdm', {
      method: 'POST',
      headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ "resource": selectElement, "o": 8 })
       }).then(response => response.text())
       .then(data => document.getElementById("response").innerHTML = data)
       .catch(error => console.log(error));
}

const intervalId = setInterval(NodesDir, 4000)





