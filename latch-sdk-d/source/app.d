//module latch;

import core.stdc.ctype;
import core.stdc.stdarg;
import core.stdc.stdlib;
import std.stdio;
import std.string;

import etc.c.curl;
//import curl/easy;

import std.digest.hmac;
//import openssl/bio
//import openssl/evp
//import openssl/buffer

// #include <time.h> => import core.time

enum AUTHORIZATION_HEADER_NAME = "Authorization";
enum DATE_HEADER_NAME = "X-11Paths-Date";
enum AUTHORIZATION_METHOD = "11PATHS";
enum AUTHORIZATION_HEADER_FIELD_SEPARATOR = " ";
enum UTC_STRING_FORMAT = "%Y-%m-%d %H:%M:%S";

enum API_CHECK_STATUS_URL = "/api/0.9/status";
enum API_PAIR_URL = "/api/0.9/pair";
enum API_PAIR_WITH_ID_URL = "/api/0.9/pairWithId";
enum API_UNPAIR_URL = "/api/0.9/unpair";
enum API_LOCK_URL = "/api/0.9/lock";
enum API_UNLOCK_URL = "/api/0.9/unlock";
enum API_HISTORY_URL = "/api/0.9/history";
enum API_OPERATION_URL = "/api/0.9/operation";

enum HTTP_METHOD_GET = "GET";
enum HTTP_METHOD_POST = "POST";
enum HTTP_METHOD_PUT = "PUT";
enum HTTP_METHOD_DELETE = "DELETE";

enum HTTP_PARAM_LOCK_ON_REQUEST = "lock_on_request";
enum HTTP_PARAM_NAME = "name";
enum HTTP_PARAM_PARENTID = "parentId";
enum HTTP_PARAM_TWO_FACTOR = "two_factor";
struct curl_response_buffer {
    char *buffer;
    size_t size;
}


alias curl_response_buffer curl_response_buffer;
struct http_param {
    char *name;
    char *value;
}

alias http_param http_param;

/*
 * Function to handle stuff from HTTP response.
 * 
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indexes
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void * buf, size_t len, size_t size, void * userdata) {

    size_t realsize = len * size;
    curl_response_buffer *response = cast(curl_response_buffer*)userdata;

    response.buffer = realloc(response.buffer, response.size + realsize + 1);

    memcpy(&(response.buffer[response.size]), buf, realsize);
    response.size += realsize;
    response.buffer[response.size] = '\0';

    return realsize;

}

/*
 * Function to encode a string in Base64 format
 * 
 * @param input- string to encode
 * @param length- string length
 * @return encoded string in Base64 format
 */

char * base64encode(const(__ubyte) *input, int length) {
	BIO *bmem;
	BIO *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = cast(char *)malloc(bptr.length);
	memcpy(buff, bptr.data, bptr.length - 1);
	buff[bptr.length - 1] = 0;

	BIO_free_all(b64);

	return buff;
}

char toHex(char code) {
    static string hex = "0123456789ABCDEF";
    return hex[code & 15];
}

/*
 * Function to percent-encode a string
 *
 * Based on http://www.geekhideout.com/downloads/urlcode.c
 */
char * urlEncode(const(char) * str, int space2Plus) {

    char * buf = null;
    char * pbuf = null;
    const(char) * pstr = str;

    if ((str !is null) && ((buf = malloc(strlen(str) * 3 + 1)) !is null)) {
        pbuf = buf;
        while (*pstr) {
            if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
                *pbuf++ = *pstr;
            } else if (*pstr == ' ' && space2Plus) {
                *pbuf++ = '+';
            } else {
                *pbuf++ = '%';
                *pbuf++ = toHex(*pstr >> 4);
                *pbuf++ = toHex(*pstr & 15);
            }
            pstr++;
        }
        *pbuf = '\0';
    }

    return buf;

}

/*
 * Function to calculate the HMAC hash (SHA1) of a string. Returns a Base64 value of the hash
 * 
 * @param pSecretKey- secret key
 * @param pData- original data to calculate the HMAC
 * @return HMAC in Base64 format
 */
char * sign_data(const(char) * pSecretKey, const(char) * pData) {
    ubyte * digest;

    digest = HMAC(EVP_sha1(), pSecretKey, strlen(pSecretKey), cast(ubyte *) pData, strlen(pData), null, null);
    return base64encode(digest, 20);
}

int nosignal = 0;
int timeout = 2;
const(char) * AppId;
const(char) * SecretKey;
const(char) * Host = "https://latch.elevenpaths.com";
const(char) * Proxy;
const(char) * tlsCAFile = null;
const(char) * tlsCAPath = null;
const(char) * tlsCRLFile = null;

void init(const(char) * pAppId, const(char) * pSecretKey) {
	AppId = pAppId;
	SecretKey = pSecretKey;
}

void setHost(const(char) * pHost){
	Host = pHost;
}

/*
 * Enable using a Proxy to connect to Latch Server
 */
void setProxy(const(char) * pProxy){
	Proxy = pProxy;
}

void setTimeout(const(int) iTimeout)
{
    timeout = iTimeout;
}

/*
 * If called with iNoSignal 1, CURLOPT_NOSIGNAL will be set to 1
 */
void setNoSignal(const(int) iNoSignal)
{
    nosignal = iNoSignal;
}

void setTLSCAFile(const(char) * pTLSCAFile)
{
    tlsCAFile = pTLSCAFile;
}

void setTLSCAPath(const(char) * pTLSCAPath)
{
    tlsCAPath = pTLSCAPath;
}

void setTLSCRLFile(const(char) * pTLSCRLFile)
{
    tlsCRLFile = pTLSCRLFile;
}

void authenticationHeaders(const(char) * pHTTPMethod, const(char) * pQueryString, char * pHeaders[], const(char) *pBody) {

	char * authHeader;
	char *dateHeader;
	char *stringToSign;
	char *b64hash;
	char utc[20];
	time_t timer;
	tm tm_info;
	int len = 0;

	time(&timer);
	gmtime_r(&timer, &tm_info);
	strftime(utc, 20, UTC_STRING_FORMAT, &tm_info);

	if (pBody is null) {
	    len = strlen(pHTTPMethod) + strlen(utc) + strlen(pQueryString) + 4;
	} else {
	    len = strlen(pHTTPMethod) + strlen(utc) + strlen(pQueryString) + strlen(pBody) + 5;
	}

	stringToSign = malloc(len);

	if (pBody is null) {
	    snprintf(stringToSign, len, "%s\n%s\n\n%s", pHTTPMethod, utc, pQueryString);
	} else {
	    snprintf(stringToSign, len, "%s\n%s\n\n%s\n%s", pHTTPMethod, utc, pQueryString, pBody);
	}

	b64hash = sign_data(SecretKey, stringToSign);

	len = strlen(AUTHORIZATION_HEADER_NAME) + strlen(AUTHORIZATION_METHOD) + strlen(AppId) + strlen(b64hash) + 5;
	authHeader = malloc(len);
	snprintf(authHeader, len, "%s: %s %s %s", AUTHORIZATION_HEADER_NAME, AUTHORIZATION_METHOD, AppId, b64hash);

	len = strlen(DATE_HEADER_NAME) + strlen(utc) + 3;
	dateHeader = malloc(len);
	snprintf(dateHeader, len, "%s: %s", DATE_HEADER_NAME, utc);

	pHeaders[0] = authHeader;
	pHeaders[1] = dateHeader;

    free(stringToSign);
    free(b64hash);

}

/*
 * Perform a GET request to the specified URL of the Latch API
 * @param pUrl- requested URL including host
 */
char * http_proxy(const(char) * pMethod, const(char) * pUrl, const(char) * pBody) {

	char * headers[2];
	curl_response_buffer response;
	char error_message[CURL_ERROR_SIZE];
	CURL* pCurl = curl_easy_init();
	int res = -1;
	int i = 0;
	curl_slist* chunk = null;
	char * hostAndUrl;

	if (!pCurl) {
		return null;
	}

    response.buffer = malloc(1*char.sizeof);
    response.size = 0;
    response.buffer[response.size] = '\0';

	authenticationHeaders(pMethod, pUrl, headers, pBody);
	for (i=0; i<(headers.sizeof/(char *).sizeof); i++) {
		chunk = curl_slist_append(chunk, headers[i]);
	}

    free(headers[0]);
    free(headers[1]);

	hostAndUrl = malloc(strlen(Host) + strlen(pUrl) + 1);
	strcpy(hostAndUrl, Host);
	strcat(hostAndUrl, pUrl);

	curl_easy_setopt(pCurl, CURLOPT_URL, hostAndUrl);
	curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
	curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);

	curl_easy_setopt(pCurl, CURLOPT_CUSTOMREQUEST, pMethod);

	if ((strncmp(pMethod, HTTP_METHOD_POST, strlen(HTTP_METHOD_POST)) == 0) || (strncmp(pMethod, HTTP_METHOD_PUT, strlen(HTTP_METHOD_PUT)) == 0)) {
	    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pBody);
	    if (pBody is null) {
	        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, 0);
	    }
	}

	if(Proxy !is null){
		curl_easy_setopt(pCurl, CURLOPT_PROXY, Proxy);
	}

	// we don't want to leave our user waiting at the login prompt forever
	curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, timeout);

	// SSL needs 16k of random stuff. We'll give it some space in RAM.
	curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1);
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

	// error message when curl_easy_perform return non-zero
	curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, error_message);

	// Optional if setNoSignal(1)
	// Avoid crashing if multithread, DNS timeout and libcurl < 7.32.0
	// Blocks with standard resolver (doesn't apply the timeout)

	if (nosignal == 1) {
	    curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1);
	}

	if (tlsCAFile !is null) {
	    curl_easy_setopt(pCurl, CURLOPT_CAINFO, tlsCAFile);
	    curl_easy_setopt(pCurl, CURLOPT_CAPATH, null);
	}
	else {
	    if (tlsCAPath !is null) {
	        curl_easy_setopt(pCurl, CURLOPT_CAINFO, null);
	        curl_easy_setopt(pCurl, CURLOPT_CAPATH, tlsCAPath);
	    }
	}

	if (tlsCRLFile !is null) {
	    curl_easy_setopt(pCurl, CURLOPT_CRLFILE, tlsCRLFile);
	}

	// synchronous, but we don't really care
	res = curl_easy_perform(pCurl);

	curl_easy_cleanup(pCurl);
    curl_slist_free_all(chunk);
    free(hostAndUrl);

    if (res != CURLE_OK) {
        free(response.buffer);
        return null;
    }
    else {
        return response.buffer;
    }

}

char * build_string(int argc, char ** argv) {

    int i = 0;
    int len = 1;
    char *rv = null;

    for (i = 0; i < argc; i++) {
        if (argv[i] !is null) {
            len += strlen(argv[i]);
        }
    }

    if ((rv = cast(char *) malloc(len)) !is null) {
        *rv = '\0';
        for (i = 0; i < argc; i++) {
            if (argv[i] !is null) {
                strncat(rv, argv[i], strlen(argv[i]));
            }
        }
    }

    return rv;

}

char * build_url(int argc, ...) {

    int i = 0;
    char *tokens[2 * argc - 1];
    char *response = null;
    va_list args;

    va_start(args, argc);
    for (i = 0; i < 2 * argc - 1; i = i + 2) {
        if (i == 0) {
            tokens[i] = va_arg(args, char* /* SYNTAX ERROR: (396): expression expected, not ) */ );
        } else {
            tokens[i] = urlEncode(va_arg(args, char* /* SYNTAX ERROR: (398): expression expected, not ) */ ), 0);
        }
        if (i < 2 * argc - 1) {
            if (tokens[i] is null) {
                tokens[i + 1] = null;
            } else {
                tokens[i + 1] = "/";
            }
        }
    }
    va_end(args);

    response = build_string(2 * argc - 1, tokens);

    for (i = 0; i < 2 * argc - 1; i = i + 2) {
        if (i != 0) {
            free(tokens[i]);
        }
    }

    return response;

}

char * build_url_v(int argc, va_list args) {

    int i = 0;
    char *tokens[2 * argc - 1];
    char *response = null;

    for (i = 0; i < 2 * argc - 1; i = i + 2) {
        if (i == 0) {
            tokens[i] = va_arg(args, char* /* SYNTAX ERROR: (430): expression expected, not ) */ );
        } else {
            tokens[i] = urlEncode(va_arg(args, char* /* SYNTAX ERROR: (432): expression expected, not ) */ ), 0);
        }
        if (i < 2 * argc - 1) {
            if (tokens[i] is null) {
                tokens[i + 1] = null;
            } else {
                tokens[i + 1] = "/";
            }
        }
    }

    response = build_string(2 * argc - 1, tokens);

    for (i = 0; i < 2 * argc - 1; i = i + 2) {
        if (i != 0) {
            free(tokens[i]);
        }
    }

    return response;

}

char * build_querystring(int argc, http_param* params) {

    int i = 0;
    int j = 0;
    char *rv = null;
    char *tokens[4 * argc];

    for (i = 0, j = 0; i < 4 * argc; i = i + 4, j++) {
        if (params[j].name !is null && params[j].value !is null) {
            tokens[i] = params[j].name;
            tokens[i + 1] = "=";
            tokens[i + 2] = params[j].value;
            tokens[i + 3] = "&";
        } else {
            tokens[i] = null;
            tokens[i + 1] = null;
            tokens[i + 2] = null;
            tokens[i + 3] = null;
        }
    }

    rv = build_string(4 * argc, tokens);
    rv[strlen(rv) - 1] = '\0';

    return rv;

}

char * operation(const(char) * pMethod, int nParams, http_param* params, int nUrlTokens, ...) {

    int i = 0;
    int valid = 1;
    char *response = null;
    char *url = null;
    char *body = null;
    va_list args;

    va_start(args, nUrlTokens);
    for (i = 0; i < nUrlTokens; i++) {
        if (va_arg(args, char* /* SYNTAX ERROR: (494): expression expected, not ) */ ) == null) {
            valid = 0;
        }
    }
    va_end args;

    va_start(args, nUrlTokens);

     /* SYNTAX ERROR: (502): expected <identifier> instead of if */  

        
             
         /* SYNTAX ERROR: unexpected trailing } */ }

        response = http_proxy(pMethod, url, body);

        free url;
        free body;

     /* SYNTAX ERROR: unexpected trailing } */ }

    va_end args;

     /* SYNTAX ERROR: (517): expected <identifier> instead of return */ 

 /* SYNTAX ERROR: unexpected trailing } */ }

char * pairWithId(const(char) * pAccountId) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_PAIR_WITH_ID_URL, pAccountId);
}

char * pair(const(char) * pToken) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_PAIR_URL, pToken);
}

char * status(const(char) * pAccountId) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_CHECK_STATUS_URL, pAccountId);
}

char * operationStatus(const(char) * pAccountId, const(char) * pOperationId) {
    return operation(HTTP_METHOD_GET, 0, null, 4, API_CHECK_STATUS_URL, pAccountId, "op", pOperationId);
}

char * unpair(const(char) * pAccountId) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_UNPAIR_URL, pAccountId);
}

char * lock(const(char) * pAccountId) {
    return operation(HTTP_METHOD_POST, 0, null, 2, API_LOCK_URL, pAccountId);
}

char * operationLock(const(char) * pAccountId, const(char) * pOperationId) {
    return operation(HTTP_METHOD_POST, 0, null, 4, API_LOCK_URL, pAccountId, "op", pOperationId);
}

char * unlock(const(char) * pAccountId) {
    return operation(HTTP_METHOD_POST, 0, null, 2, API_UNLOCK_URL, pAccountId);
}

char * operationUnlock(const(char) * pAccountId, const(char) * pOperationId) {
    return operation(HTTP_METHOD_POST, 0, null, 4, API_UNLOCK_URL, pAccountId, "op", pOperationId);
}

char * history(const(char) * pAccountId) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_HISTORY_URL, pAccountId);
}

char * timePeriodHistory(const(char) * pAccountId, time_t from, time_t to) {

    char sFrom[14];
    char sTo[14];

    if (from == 0) {
        snprintf(sFrom, 14, "%lld", cast(long)from);
    } else {
        snprintf(sFrom, 14, "%lld000", cast(long)from);
    }

    if (to == 0) {
        snprintf(sTo, 14, "%lld", cast(long)to);
    } else {
        snprintf(sTo, 14, "%lld000", cast(long)to);
    }

    return operation(HTTP_METHOD_GET, 0, null, 4, API_HISTORY_URL, pAccountId, sFrom, sTo);

}

char * operationCreate(const(char) * pParentId, const(char) * pName, const(char) * pTwoFactor, const(char) * pLockOnRequest) {

    char *response = null;
    http_param params[4];

    if (pParentId !is null && pName !is null) {

        params[0].name = HTTP_PARAM_LOCK_ON_REQUEST;
        params[0].value = pLockOnRequest is null ? null : urlEncode(pLockOnRequest, 1);
        params[1].name = HTTP_PARAM_NAME;
        params[1].value = urlEncode(pName, 1);
        params[2].name = HTTP_PARAM_PARENTID;
        params[2].value = urlEncode(pParentId, 1);
        params[3].name = HTTP_PARAM_TWO_FACTOR;
        params[3].value = pTwoFactor is null ? null : urlEncode(pTwoFactor, 1);

        response = operation(HTTP_METHOD_PUT, 4, params, 1, API_OPERATION_URL);

        free(params[0].value);
        free(params[1].value);
        free(params[2].value);
        free(params[3].value);

    }

    return response;

}

char * operationUpdate(const(char) * pOperationId, const(char) * pName, const(char) * pTwoFactor, const(char) * pLockOnRequest) {

    char *response = null;
    http_param params[3];

    if (pOperationId !is null && (pName !is null || pTwoFactor !is null || pLockOnRequest !is null)) {

        params[0].name = HTTP_PARAM_LOCK_ON_REQUEST;
        params[0].value = pLockOnRequest is null ? null : urlEncode(pLockOnRequest, 1);
        params[1].name = HTTP_PARAM_NAME;
        params[1].value = pName is null ? null : urlEncode(pName, 1);
        params[2].name = HTTP_PARAM_TWO_FACTOR;
        params[2].value = pTwoFactor is null ? null : urlEncode(pTwoFactor, 1);

        response = operation(HTTP_METHOD_POST, 3, params, 2, API_OPERATION_URL, pOperationId);

        free(params[0].value);
        free(params[1].value);
        free(params[2].value);

    }

    return response;

}

char * operationRemove(const(char) * pOperationId) {
    return operation(HTTP_METHOD_DELETE, 0, null, 2, API_OPERATION_URL, pOperationId);
}

char * operationGet(const(char) * pOperationId) {
    return operation(HTTP_METHOD_GET, 0, null, 2, API_OPERATION_URL, pOperationId);
}

char * operationsGet() {
    return operation(HTTP_METHOD_GET, 0, null, 1, API_OPERATION_URL);
}

//void main()
//{
//	writeln("Edit source/app.d to start your project.");
//}
