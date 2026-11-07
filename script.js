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
