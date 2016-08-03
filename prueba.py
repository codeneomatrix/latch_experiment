 
import latch

idcuenta=""
estado=""

appId="PALPPPT7e7s4bfHmsidZ"

codigo=""

api = latch.Latch(appId, "ZETW9jibcBFF2hq3yJVMb4upfBTm9TYzeeNBia32")

response = api.pair(codigo)
responseData = response.get_data()
if responseData["accountId"]:
    idcuenta=responseData["accountId"]
else:
    print "Error"
    print responseData

response = api.status(idcuenta)
responseData = response.get_data()
if responseData["operations"]:
    estado= responseData["operations"][appId]["status"]
else:
    print "error"


response = api.unpair(idcuenta)