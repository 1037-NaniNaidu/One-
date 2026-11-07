/* Areev Sales Manager
   Local-first storage with optional encrypted Google Drive app-data backup.
   Firebase has been completely removed.
*/
const $ = (id) => document.getElementById(id);
const todayKey = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
};
const money = (n) => "₹" + Number(n || 0).toLocaleString("en-IN",{minimumFractionDigits:2,maximumFractionDigits:2});
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
const escapeHtml = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const cleanPhone = (s) => String(s).replace(/\D/g,"");
const accountKeyFor = (business, phone) => {
  const source = `${business.trim().toLowerCase()}|${cleanPhone(phone)}`;
  let h = 2166136261;
  for (let i=0;i<source.length;i++){h ^= source.charCodeAt(i);h = Math.imul(h,16777619);}
  return (h>>>0).toString(16).padStart(8,"0");
};

let account = null, accountKey = "", data = emptyData(), cart = [], saveTimer = null, lastDay = todayKey();
let driveAccessToken = null, driveTokenClient = null, pendingDriveAction = null;
const LOCAL_PREFIX = "areev_sales_manager_local_v2_";
const CLIENT_ID_KEY = "areev_sales_manager_google_client_id";

function emptyData(){
  return {products:[],customers:[],sales:[],notes:{},trash:[],ledger:[],updatedAt:new Date().toISOString()};
}

function localStorageKey(){return LOCAL_PREFIX + accountKey;}

function showAuth(message="", isSuccess=false){
  $("authScreen").classList.remove("hidden");
  $("app").classList.add("hidden");
  $("authMessage").textContent=message;
  $("authMessage").className="message"+(isSuccess?" success":"");
}

function showApp(){
  $("authScreen").classList.add("hidden");
  $("app").classList.remove("hidden");
  $("headerBusiness").textContent=account.businessName;
  $("profileDetails").textContent=`Business: ${account.businessName} · Phone: ${account.phone}`;
  $("googleClientId").value=localStorage.getItem(CLIENT_ID_KEY)||"";
  showPage("dashboard");
  renderAll();
}

function loadLocalData(){
  const raw=localStorage.getItem(localStorageKey());
  if(raw){
    try{
      const saved=JSON.parse(raw);
      data={...emptyData(),...(saved.data||saved)};
      if(!data.notes)data.notes={};
      if(!Array.isArray(data.trash))data.trash=[];
      return true;
    }catch(e){
      console.error("Saved local data could not be read",e);
    }
  }
  data=emptyData();
  saveLocal(true);
  return false;
}

function saveLocal(silent=false){
  if(!accountKey)return;
  data.updatedAt=new Date().toISOString();
  try{
    localStorage.setItem(localStorageKey(),JSON.stringify({account,data}));
    if(!silent && $("noteSaveStatus")){
      $("noteSaveStatus").textContent="Saved on this device";
    }
  }catch(error){
    console.error(error);
    if($("noteSaveStatus")){
      $("noteSaveStatus").textContent="Save failed — device storage may be full";
    }
  }
}

function queueSave(){
  clearTimeout(saveTimer);
  saveTimer=setTimeout(()=>saveLocal(),400);
}

function logout(){
  account=null;
  accountKey="";
  data=emptyData();
  cart=[];
  driveAccessToken=null;
  showAuth();
}

/* Google Drive backup uses the private appDataFolder and encrypts the backup
   with the business password before upload. Only this app can access this folder. */

function setDriveStatus(message, success=false){
  const el=$("driveStatus");
  if(el){
    el.textContent=message;
    el.className="message"+(success?" success":"");
  }
}

function getGoogleClientId(){
  return (localStorage.getItem(CLIENT_ID_KEY)||"").trim();
}

function initDriveTokenClient(){
  const clientId=getGoogleClientId();
  if(!clientId){
    setDriveStatus("Enter and save your Google OAuth Client ID first.");
    return false;
  }
  if(!window.google?.accounts?.oauth2){
    setDriveStatus("Google sign-in library is still loading. Wait a moment and try again.");
    return false;
  }
  driveTokenClient=google.accounts.oauth2.initTokenClient({
    client_id:clientId,
    scope:"https://www.googleapis.com/auth/drive.appdata",
    callback:(response)=>{
      if(response.error){
        setDriveStatus("Google Drive connection failed: "+response.error);
        return;
      }
      driveAccessToken=response.access_token;
      setDriveStatus("Google Drive connected for this session.",true);
      if(pendingDriveAction){
        const action=pendingDriveAction;
        pendingDriveAction=null;
        action();
      }
    }
  });
  return true;
}

function connectDrive(action){
  pendingDriveAction=action||null;
  if(!initDriveTokenClient())return;
  driveTokenClient.requestAccessToken({prompt:driveAccessToken?"":"consent"});
}

async function deriveEncryptionKey(password,salt){
  const enc=new TextEncoder();
  const baseKey=await crypto.subtle.importKey(
    "raw",enc.encode(password),"PBKDF2",false,["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2",salt,iterations:250000,hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM",length:256},
    false,
    ["encrypt","decrypt"]
  );
}

async function encryptBackup(password,payload){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveEncryptionKey(password,salt);
  const encrypted=await crypto.subtle.encrypt(
    {name:"AES-GCM",iv},
    key,
    new TextEncoder().encode(JSON.stringify(payload))
  );
  const bytes=new Uint8Array(encrypted);
  const combined=new Uint8Array(salt.length+iv.length+bytes.length);
  combined.set(salt,0);
  combined.set(iv,salt.length);
  combined.set(bytes,salt.length+iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptBackup(password,encoded){
  const raw=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
  const salt=raw.slice(0,16);
  const iv=raw.slice(16,28);
  const encrypted=raw.slice(28);
  const key=await deriveEncryptionKey(password,salt);
  const decrypted=await crypto.subtle.decrypt(
    {name:"AES-GCM",iv},
    key,
    encrypted
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

async function driveRequest(url,options={}){
  if(!driveAccessToken)throw new Error("Connect Google Drive first.");
  const response=await fetch(url,{
    ...options,
    headers:{
      ...(options.headers||{}),
      Authorization:"Bearer "+driveAccessToken
    }
  });
  if(!response.ok){
    const message=await response.text();
    throw new Error("Google Drive error: "+message);
  }
  if(response.status===204)return null;
  return response.json();
}

async function findDriveBackup(){
  const result=await driveRequest(
    "https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=name%3D%27areev-sales-backup.json%27&fields=files(id,name)"
  );
  return result.files?.[0]||null;
}

async function uploadDriveBackup(){
  if(!account){
    setDriveStatus("Open your business workspace first.");
    return;
  }
  const password=$("password").value;
  if(!password){
    setDriveStatus("Enter your business password on the login screen first.");
    return;
  }
  try{
    setDriveStatus("Preparing encrypted backup...");
    const encrypted=await encryptBackup(password,{account,data});
    const existing=await findDriveBackup();
    const metadata={
      name:"areev-sales-backup.json",
      mimeType:"application/json",
      ...(existing?{}:{parents:["appDataFolder"]})
    };
    const boundary="-------areevbackupboundary";
    const body=
      "--"+boundary+"\r\n"+
      "Content-Type: application/json; charset=UTF-8\r\n\r\n"+
      JSON.stringify(metadata)+"\r\n"+
      "--"+boundary+"\r\n"+
      "Content-Type: application/json\r\n\r\n"+
      JSON.stringify({encrypted})+"\r\n"+
      "--"+boundary+"--";
    const url=existing
      ?`https://www.googleapis.com/upload/drive/v3/files/${existing.id}?uploadType=multipart`
      :"https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
    await driveRequest(url,{
      method:existing?"PATCH":"POST",
      headers:{"Content-Type":"multipart/related; boundary="+boundary},
      body
    });
    setDriveStatus("Encrypted backup uploaded successfully.",true);
  }catch(error){
    console.error(error);
    setDriveStatus(error.message||"Backup failed.");
  }
}

async function restoreDriveBackup(){
  const password=$("password").value;
  if(!password){
    setDriveStatus("Enter your business password first.");
    return;
  }
  try{
    setDriveStatus("Searching for your backup...");
    const file=await findDriveBackup();
    if(!file){
      setDriveStatus("No backup was found in this Google Drive account.");
      return;
    }
    const result=await driveRequest(
      `https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`
    );
    const restored=await decryptBackup(password,result.encrypted);
    if(!restored.account||!restored.data){
      throw new Error("Backup file format is not valid.");
    }
    const expected=accountKeyFor(restored.account.businessName,restored.account.phone);
    if(expected!==accountKey){
      throw new Error("This backup belongs to a different business or phone number.");
    }
    data={...emptyData(),...restored.data};
    saveLocal();
    renderAll();
    setDriveStatus("Backup restored successfully.",true);
  }catch(error){
    console.error(error);
    setDriveStatus("Restore failed. Check your password and backup. "+error.message);
  }
}

/* Authentication and workspace entry */

$("authForm").addEventListener("submit",async e=>{
  e.preventDefault();
  const businessName=$("businessName").value.trim();
  const phone=$("phoneNumber").value.trim();
  const password=$("password").value;
  if(businessName.length<2){
    showAuth("Please enter a valid business name.");
    return;
  }
  if(cleanPhone(phone).length<7){
    showAuth("Please enter a valid phone number.");
    return;
  }
  if(password.length<6){
    showAuth("Password must contain at least 6 characters.");
    return;
  }
  const button=$("authForm").querySelector('button[type="submit"]');
  if(button)button.disabled=true;
  try{
    account={businessName,phone};
    accountKey=accountKeyFor(businessName,phone);
    loadLocalData();
    showApp();
  }catch(error){
    console.error(error);
    showAuth("Unable to open your workspace. Please try again.");
  }finally{
    if(button)button.disabled=false;
  }
});
