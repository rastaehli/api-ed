from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from orm import Parameter, RestCall, db_connection_info

# set db connection info
engine = create_engine(db_connection_info)
# bind Obj-Relational Mapping in "orm" module to this database
#Base.metadata.bind = engine
# get DB session for this database
Session = sessionmaker(bind=engine)
session = Session()

def getAll(c):
    return session.query(c).all()

def getFirst(c):
    return getAll(c)[0]

def deleteAll():
    for x in session.query(RestCall):
        session.delete(x)
    session.commit
    for x in session.query(Parameter):
        session.delete(x)
    session.commit
    session.commit

def createRestCall(method, path, description, exampleRequest, exampleResponse):
    call = RestCall(method, path, description, exampleRequest, exampleResponse)
    session.add(call)
    session.commit()

def addParameter(restCall, type, name, range, description):
    restCall.parameters.add(
    	Parameter(restCall, type, name, range, description))
    session.add(restCall)
    session.commit()

deleteAll()

tokenDescription = 'Valid token value from POST /access/token response.'
tokenExample = '"Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'

call = RestCall('GET', 'shipments', 'me'
	).requireQueryParam('ref', 'String, 3 to 12 characters long.', 'A (prefix of a) trace value associated with a shipment.', '5555'
	).optionalQueryParam('sizelimit', 'Integer, 1 to 10000', 'Maximum number of items to return.', '1000'
	).optionalQueryParam('offset', 'Integer, 0 to maxint', 'Starting offset to return the next sizelimit items from list of matching items.', '0'
	).setDescription('Get a list information for client shipments with trace values matching the given {ref}.'
	).requireAuthenticationBearerToken(tokenDescription, tokenExample
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'GET /v1/shipments?ref=5555 HTTP/1.1\n'+
		'Host: api.expeditors.com\n'+
		'Authorization: Bearer "Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'
	).setExampleResponse(
		'HTTP/1.1 200 OK\n'+
		'Content-Type: application/json;charset=UTF-8\n'+
		'Cache-Control: no-store\n'+
		'Pragma: no-cache\n'+
		'\n'+
		'[\n'+
		'	{\n'+
		'    "shipment_number": "1234567890",\n'+
		'    "status": "Completed",\n'+
		'    "origin": "San Francisco",\n'+
		'    "destination": "Hong Kong",\n'+
		'    "arrived_at_destination": "2016-02-16 00:00:00+8:00"\n'+
		'  },\n'+
		'  {\n'+
		'    "shipment_number": "abcdefghij",\n'+
		'    "status": "In Transit",\n'+
		'    "origin": "San Francisco",\n'+
		'    "destination": "Hong Kong",\n'+
		'    "arrived_at_destination": "2016-02-16 00:00:00+8:00"\n'+
		'  }\n'+
		']')
session.add(call)
session.commit()

call = RestCall('GET', 'shipments/count', 'me'
	).requireQueryParam('ref', 'String, 3 to 12 characters long.', 'A (prefix of a) trace value associated with a shipment.', '5555'
	).setDescription('Get the total count of client shipments with trace values matching the given {ref}.'
	).requireAuthenticationBearerToken(tokenDescription, tokenExample
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'GET /v1/shipments/count?ref=5555 HTTP/1.1\n'+
		'Host: api.expeditors.com\n'+
		'Authorization: Bearer "Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'
	).setExampleResponse(
		'HTTP/1.1 200 OK\n'+
		'Content-Type: application/json;charset=UTF-8\n'+
		'Cache-Control: no-store\n'+
		'Pragma: no-cache\n'+
		'\n'+
		'{ "count": 456 }')
session.add(call)
session.commit()
 

call = RestCall('GET', 'shipments/{id}', 'me'
	).requirePathParam('id', 'String, 3 to 12 characters long.', 'Unique identifier for an Expeditors shipment, URL-encoded.', '2123456789'
	).setDescription('Get information about shipment with the given {id}.'
	).requireAuthenticationBearerToken(tokenDescription, tokenExample
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'GET /v1/shipments/9012345678 HTTP/1.1\n'+
		'Host: api.expeditors.com\n'+
		'Authorization: Bearer "Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'
	).setExampleResponse(
		'HTTP/1.1 200 OK\n'+
    	'Content-Type: application/json;charset=UTF-8\n'+
    	'Cache-Control: no-store\n'+
    	'Pragma: no-cache\n'+
    	' \n'+
    	'{\n'+
    	'    "shipment_number": "abcdefghij",\n'+
    	'    "status": "In Transit",\n'+
    	'    "origin": "San Francisco",\n'+
    	'    "destination": "Hong Kong",\n'+
    	'    "arrived_at_destination": "2016-02-16 00:00:00+8:00"\n'+
    	' }')
session.add(call)
session.commit()
 

call = RestCall('GET', 'shipments/{id}/events', 'me'
	).requirePathParam('id', 'String, 3 to 12 characters long.', 'Unique identifier for an Expeditors shipment, URL-encoded.', '2123456789'
	).setDescription('Get a list of events for client shipment with the given {id}.'
	).requireAuthenticationBearerToken(tokenDescription, tokenExample
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'GET /v1/shipments/9012345678/events HTTP/1.1\n'+
		'Host: api.expeditors.com\n'+
		'Authorization: Bearer "Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'
	).setExampleResponse(
		'HTTP/1.1 200 OK\n'+
    	'Content-Type: application/json;charset=UTF-8\n'+
    	'Cache-Control: no-store\n'+
    	'Pragma: no-cache\n'+
    	' \n'+
 		'[\n'+
		'  {\n'+
 		'   "Origin": null\n'+
 		'   "Destination": "TACOMA, WA (TCM)"\n'+
		'    "Description": "Liquidated"\n'+
		'    "Invoice": "7031326393"\n'+
		'    "Event Date": "2014-11-28 12:00:00.0"\n'+
		'    "Remarks": "No Change 00"\n'+
		'    "Event Date Timezone offset": "0"\n'+
		'    "TLA": "LIQ"\n'+
		'  },\n'+
		'  {\n'+
		'    "Origin": null\n'+
		'    "Destination": "TACOMA, WA (TCM)"\n'+
		'    "Description": "Expected Monthly Pmt Date"\n'+
		'    "Invoice": "7031324022"\n'+
		'    "Event Date": "2014-02-24 12:00:00.0"\n'+
		'    "Remarks": null\n'+
		'    "Event Date Timezone offset": "0"\n'+
		'    "TLA": "ESM"\n'+
		'  }\n'+
		']')
session.add(call)
session.commit()
 
 
call = RestCall('GET', 'shipments/{id}/references', 'me'
	).requirePathParam('id', 'String, 3 to 12 characters long.', 'Unique identifier for an Expeditors shipment, URL-encoded.', '2123456789'
	).setDescription('Get a list of references for client shipment with the given {id}.'
	).requireAuthenticationBearerToken(tokenDescription, tokenExample
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'GET /v1/shipments/9012345678/references HTTP/1.1\n'+
		'Host: api.expeditors.com\n'+
		'Authorization: Bearer "Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic"'
	).setExampleResponse(
		'HTTP/1.1 200 OK\n'+
    	'Content-Type: application/json;charset=UTF-8\n'+
    	'Cache-Control: no-store\n'+
    	'Pragma: no-cache\n'+
    	'\n'+
 		'[\n'+
		'  {\n'+
 		'   "type": "Purchase Order",\n'+
 		'   "reference": "PO-12345"\n'+
		'  },\n'+
		'  {\n'+
 		'   "type": "Purchase Order",\n'+
 		'   "reference": "PO-21345"\n'+
		'  }\n'+
		']')
session.add(call)
session.commit()

 
call = RestCall('POST', 'access/token', 'me'
	).setDescription('Request an access token by POSTing client credentials. Visibility validates that the client with these credentials is registered to use the API. It then generates a non-forgeable, strongly encrypted token that identifies this client.'
	).requireAuthenticationBasicCredentials('The Expeditors API registration process generates a unique client_id and password.  Construct the client credentials by formatting these as {client_id}:{password}, the Base64 encoding this string.', 'czZCaGRSa3F0MzpnWDFmQmF0M2JW'
	).requireBodyParam('grant_type', '"client_credentials" is the only value currently supported.', 'Identifies the type of access required.', '"client_credentials"'
	).setResponseFormatJSON(
    ).setExampleRequest(
    	'POST /v1/access/token HTTP/1.1\n'+
    	'Host: server.example.com\n'+
    	'Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW\n'+
    	'Content-Type: application/x-www-form-urlencoded\n'+
     	'\n'+
    	'grant_type=client_credentials '
	).setExampleResponse(
    	'HTTP/1.1 200 OK\n'+
    	'Content-Type: application/json;charset=UTF-8\n'+
    	'Cache-Control: no-store\n'+
    	'Pragma: no-cache\n'+
    	'\n'+
    	'{\n'+
    	'                "access_token":"Ejr2YotnFZFEjr1zCsicMWpAAotnFZFEjr1zCsic",\n'+
    	'                "token_type":"bearer",\n'+
    	'                "expires_in":3600,\n'+
    	'                "scope":"application"\n'+
    	'} ')
session.add(call)
session.commit()


call = RestCall('GET', 'webcheck', 'me'
	).setDescription('Request confirmation web service is available.'
	).setResponseFormatTextPlain(
    ).setExampleRequest(
     	'GET /v1/webcheck HTTP/1.1\n'+
     	'Host: api.expeditors.com '
	).setExampleResponse(
    	'HTTP/1.1 200 OK\n'+
    	'Content-Type: text/plain;charset=UTF-8\n'+
    	'Cache-Control: no-store\n'+
    	'Pragma: no-cache\n'+
    	'\n'+
    	'api service status is OK')
session.add(call)
session.commit()
