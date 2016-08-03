var latch = require('latch-sdk');

var appid="PALPPPT7e7s4bfHmsidZ"

latch.init({ appId: appid, secretKey: 'ZETW9jibcBFF2hq3yJVMb4upfBTm9TYzeeNBia32'});

var datos="";
var idcuenta="";
var codigo="";


 var pairResponse = latch.pair(codigo, function(err, data) {
                datos=data
                if (data["data"]) {
                    idcuenta=data["data"]["accountId"]
                    console.log(data["data"]["accountId"]);
                }
                if (data["error"]) {
                console.log(data["error"]["code"]);
                    console.log(data["error"]["message"]);
                }
                
     });


    latch.status(idcuenta, function(err, data) {
        datos= data;
        if (datos["data"]) {
            console.log(datos["data"]["operations"][appid]["status"])
        }
        if (data["error"]) {
            console.log(data["error"]["code"]);
            console.log(data["error"]["message"]);
        }
    });


datos["data"]["operations"][appid]["status"]



latch.unpair(idcuenta, function(err, data) {
        datos=data
        console.log(datos)
    });


