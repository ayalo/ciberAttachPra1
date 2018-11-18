local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local tls = require "tls"
local unicode = require "unicode"

description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Not valid before: 2011-03-23 00:00:00
|_Not valid after:  2013-04-01 23:59:59
</code>

With <code>-v</code> it adds the issuer name and fingerprints.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
|_SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
</code>

With <code>-vv</code> it adds the PEM-encoded contents of the entire
certificate.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US/1.3.6.1.4.1.311.60.2.1.2=Delaware\
/postalCode=95131-2021/localityName=San Jose/serialNumber=3014267\
/streetAddress=2211 N 1st St/1.3.6.1.4.1.311.60.2.1.3=US\
/organizationalUnitName=PayPal Production/businessCategory=Private Organization
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US\
/organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
| SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
| -----BEGIN CERTIFICATE-----
| MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
...
| 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
|_-----END CERTIFICATE-----
</code>
]]

---
-- @see ssl-cert-intaddr
--
-- @output
-- 443/tcp open  https
-- | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
-- /stateOrProvinceName=California/countryName=US
-- | Not valid before: 2011-03-23 00:00:00
-- |_Not valid after:  2013-04-01 23:59:59
--
-- @xmloutput
-- <table key="subject">
--   <elem key="1.3.6.1.4.1.311.60.2.1.2">Delaware</elem>
--   <elem key="1.3.6.1.4.1.311.60.2.1.3">US</elem>
--   <elem key="postalCode">95131-2021</elem>
--   <elem key="localityName">San Jose</elem>
--   <elem key="serialNumber">3014267</elem>
--   <elem key="countryName">US</elem>
--   <elem key="stateOrProvinceName">California</elem>
--   <elem key="streetAddress">2211 N 1st St</elem>
--   <elem key="organizationalUnitName">PayPal Production</elem>
--   <elem key="commonName">www.paypal.com</elem>
--   <elem key="organizationName">PayPal, Inc.</elem>
--   <elem key="businessCategory">Private Organization</elem>
-- </table>
-- <table key="issuer">
--   <elem key="organizationalUnitName">Terms of use at https://www.verisign.com/rpa (c)06</elem>
--   <elem key="organizationName">VeriSign, Inc.</elem>
--   <elem key="commonName">VeriSign Class 3 Extended Validation SSL CA</elem>
--   <elem key="countryName">US</elem>
-- </table>
-- <table key="pubkey">
--   <elem key="type">rsa</elem>
--   <elem key="bits">2048</elem>
-- </table>
-- <elem key="sig_algo">sha1WithRSAEncryption</elem>
-- <table key="validity">
--   <elem key="notBefore">2011-03-23T00:00:00+00:00</elem>
--   <elem key="notAfter">2013-04-01T23:59:59+00:00</elem>
-- </table>
-- <elem key="md5">bf47cecad861efa77d1488ad4a73cb5b</elem>
-- <elem key="sha1">d8465221467a0d153df09f2eaf6d439002139a68</elem>
-- <elem key="pem">-----BEGIN CERTIFICATE-----
-- MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
-- ...
-- 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
-- -----END CERTIFICATE-----
-- </elem>

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }


portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return stdnse.format_timestamp(date)
  end
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = stdnse.strjoin(".", k)
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return stdnse.strjoin("/", fields)
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = stdnse.strjoin(".", k)
    end
    output[k] = v
  end
  return output
end

local function output_tab(cert)
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)
  o.pubkey = cert.pubkey
  o.extensions = cert.extensions
  o.sig_algo = cert.sig_algorithm
  o.validity = {}
  for k, v in pairs(cert.validity) do
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = stdnse.format_timestamp(v)
    end
  end
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  o.pem = cert.pem
  return o
end

local function output_str(cert)
  local lines = {}

  lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
    lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
    lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm
  end

  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end
  return stdnse.strjoin("\n", lines)
end


----------From here our code ---------------------------------------------------------------------
-- Function to split strings 
-- @input string, and the possition in the tuple that we want to be our register 
-- @output array arr that contains a list with suspicious DNS in one column
function split(str,reg)

	local arr =  {}
	 for val in string.gmatch(str,reg) do 
		 table.insert(arr,val)
	end
	return arr
end

-- Function to load suspicious from file
-- @input file with a list of suspicious DNSs (list.csv)
-- for each line in the file, read it like a tuple of 3 elements separated by ';' and get the third one which indicates the DNS
-- arr is an array wich will contain 'true' if the value obtained before is a suspicious DNS or 'false'if is not suspicious.
-- @output arr, booleans array, for each position arr[suspicious_DNS] = 'true/false'
function load_suspicious(file_name)
	 local file = io.open(file_name, "r");
	 local arr = {}
	 for line in file:lines() do

		 stdnse.debug1(" line ,%s ",line)
		 suspicious_dns=split(line,'([^;]+)')[3]
		 arr[suspicious_dns]=true

	 end

	 return arr
 end

-- Function to check if a SubjectAltName is suspicious 
-- @input certificate and the suspicious DNS list
-- if the suspicious list is null, list.csv is asigned as second argument list_suspicious_DNS
-- if list_suspicious_DNS has value, compares with the file passed like argument
function check_an(cert,list_suspicious_DNS)
        if not list_suspicious_DNS then
		list_suspicious_DNS="list.csv"
	end
	suspicious_list=load_suspicious(list_suspicious_DNS)
        print ("Suspicious list used : ",list_suspicious_DNS)
	stdnse.debug1(" DNSs suspisious, %s ",table.concat(suspicious_list,","))

	if cert.extensions then
		for _,e in ipairs(cert.extensions) do 
			if e.name == "X509v3 Subject Alternative Name" then
				stdnse.debug1("cert AN: %s ",e.name)
				stdnse.debug1(" cert AN values %s ",e.value)
				for val in string.gmatch(e.value,'([^,]+)') do 
					stdnse.debug1("value in list ,%s ",val)
					check_dns=split(val,'([^:]+)')[2] 
					-- we get the value after ':' 

					if suspicious_list[check_dns] then  
						-- If we have a true in the previous checking 
						stdnse.debug1(" This is a SUSPICIOUS DNS, %s ",check_dns)
						print ("WARNING: Suspicious DNS found :", check_dns)
					end
				end

			end
		end
	end
end

-- Function to get the extensions part of a certificate
-- @input first argument: certificate, and second argument: name of the extension that we are looking for in the certificate.
-- @output extension found in the certificate or 'This extension doesn't exists.' if there isn't this part in the certificate.
function get_extension(cert,extension)

	if cert.extensions then  
		-- cert.extensions is defined on the previous code on the script, so we use it.
		for _,e in ipairs(cert.extensions)do
			stdnse.debug1(" extensiones  %s ",e.name)
			if e.name == extension then
				stdnse.debug1(" extension find , %s",extension)
				return e
			end
		end
	end
	return "This extension doesn't exists."
end

-- Function to find the extension "Subject Key Identifier" in the certificate.
-- @input certificate in which we are looking for
function print_key_identi(cert)	

	local key_identi_extension=get_extension(cert,"X509v3 Subject Key Identifier")
	stdnse.debug1(" key identifier  %s ",key_identi_extension.value)

	local length_extension=#split(key_identi_extension.value,'([^:]+)')

	stdnse.debug1("tamaño  : %d ",length_extension)
-- OJO quitar >= y generar uno para hacer los casos de prueba
	if length_extension>20 then 
		stdnse.debug1("WARNING: Length too big. More than 20 bytes.")
		print ("WARNING: X509v3 Subject Key Identifier lenght bigger than 20 bytes.")
	end
end

-- Function to check the validity date of the certificate
-- @input certificate and string with the date we want to compare with
-- if there is no date to compare always compare with the current date
function check_validity(cert, compare_date)

	local validity_not_before= cert.validity.notBefore
	local validity_not_after= cert.validity.notAfter
	local actual_date
	if not compare_date then 
		converted_date = os.time()
		
	else
		local pattern = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)"
		local year, month, day, hour, min, sec = compare_date:match(pattern)
		converted_date = os.time({year=year, month=month, day=day, hour=hour, min=min, sec=sec})

	end
	print ("Given date timestamp: ",converted_date)
	print ("Given date: ",date_to_string(converted_date))
	--year = tonumber(os.date('%Y',time))
        --month = tonumber(os.date('%m',time))
	--day = tonumber(os.date('%d',time))
 	--h = tonumber(os.date('%H', time))
	--m = tonumber(os.date('%M',time))
	--s = tonumber(os.date('%S',time))

	--print ("TODAY : ",day,month,year,h,m,s)
	stdnse.debug1("Compare_date : ",date_to_string(converted_date))
	stdnse.debug1("Validity.notBefore in cert : %s ",date_to_string(validity_not_before))
	stdnse.debug1("Validity.notAfter in cert : %s ",date_to_string(validity_not_after))
--local pattern = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)"
-- local  actual_date= "2018-11-11 19:24:31" -- same date as the cert10
-- local actual_date="2017-11-11 22:13:40" -- Not in time
-- local actual_date="2019-02-26 12:34:00" -- OK in period is valid 
-- local actual_date="2020-04-23 22:45:12" -- Not in time
--local year, month, day, hour, min, sec = actual_date:match(pattern)
--local converted_date = os.time({year=year, month=month, day=day, hour=hour, min=min, sec=sec})
--print("Tiempo en timestamp",converted_date)

local dateBefore=os.time(validity_not_before)
print ("DateBefore timestamp: ",dateBefore)
print ("DateBefore: ",date_to_string(validity_not_before))
local dateAfter=os.time(validity_not_after)
print ("DateAfter timestamp: ", dateAfter)
print ("DateAfter: ",date_to_string(validity_not_after))
print ("Comparando  ")
if converted_date >= dateBefore and converted_date <=dateAfter then 
	print ("Certificate Validity date OK in period")
else
	print (" WARNING : The certificate Validity date is not in time.")
end


end

-- Not used
function get_args(...)
   for i,k in ipairs {...} do
	   print (i, k)
   end	   
end
------------------ End our code -------------------------------------------------------------
action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  --local list_suspicious_DNS="list.csv"
  -- our functions ---
  print_key_identi(cert)	
  check_validity(cert,nmap.registry.args.date)
  stdnse.debug1("Looking for suspicious DNS ... ")
 
  check_an(cert,nmap.registry.args.list)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end
  -- end calls to our functions ---

  return output_tab(cert), output_str(cert)
end



