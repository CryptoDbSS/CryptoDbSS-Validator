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
            if( elemento == "unsynced" ){
              const circleElement = document.querySelector('.circle'); // Seleccionar el elemento con la clase 'circle'
  
              circleElement.style.backgroundColor = "rgb(219, 99, 99)"; // Cambiar el color de fondo a rojo
            }
            if( elemento == "syncing..." ){
              const circleElement = document.querySelector('.circle'); // Seleccionar el elemento con la clase 'circle'
  
              circleElement.style.backgroundColor = "rgb(255, 224, 103)"; // Cambiar el color de fondo a rojo
            }
          }
        });
  
  
        // Realiza cualquier otra operación con cada elemento aquí
      });
    })
    .catch(function(error) {
      console.log('Error:', error);
    });
  }, 2300);