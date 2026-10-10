import { getStore } from "@netlify/blobs";
import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";

const store = () => getStore({ name: "port-kinshasa-secure", consistency: "strong" });
const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {
  status, headers: { "content-type":"application/json; charset=utf-8", "cache-control":"no-store", ...extra }
});
const cookieName = "pk_session";
const secret = () => process.env.SESSION_SECRET;
function hash(pw, salt=randomBytes(16).toString("hex")) {
  return {salt, hash:scryptSync(String(pw), salt, 64).toString("hex")};
}
function verify(pw, rec) {
  if (!rec?.salt || !rec?.hash) return false;
  const a=scryptSync(String(pw),rec.salt,64), b=Buffer.from(rec.hash,"hex");
  return a.length===b.length && timingSafeEqual(a,b);
}
function sign(value) {
  const key = secret();
  if (!key || key.length < 32) throw new Error("Configuration serveur incomplète : définissez SESSION_SECRET (au moins 32 caractères) dans les variables d’environnement Netlify, puis redéployez.");
  return createHmac("sha256", key).update(value).digest("hex");
}
function makeCookie(payload) {
  const value=Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${cookieName}=${value}.${sign(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}
async function session(req) {
  if (!secret()) throw new Error("SESSION_SECRET manquant dans les variables Netlify.");
  const c=(req.headers.get("cookie")||"").split("; ").find(x=>x.startsWith(cookieName+"="));
  if (!c) return null;
  const token=c.slice(cookieName.length+1), i=token.lastIndexOf(".");
  if(i<0) return null;
  const value=token.slice(0,i), sig=token.slice(i+1);
  if(sign(value)!==sig) return null;
  try { const s=JSON.parse(Buffer.from(value,"base64url").toString()); return s.exp>Date.now()?s:null; } catch { return null; }
}
async function get(key, fallback) { return await (await store()).get(key,{type:"json"}) ?? fallback; }
async function put(key, value) { await (await store()).setJSON(key,value); }
function has(user, perm) { return user?.role==="admin" || user?.permissions?.[perm]===true; }
function kinshasaParts(date=new Date()) {
  const parts = new Intl.DateTimeFormat("en-CA", {timeZone:"Africa/Kinshasa", year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", hourCycle:"h23"}).formatToParts(date);
  return Object.fromEntries(parts.filter(p=>p.type!=="literal").map(p=>[p.type,p.value]));
}
function cardValid(c, now) {
  const day=kinshasaParts(now).year+"-"+kinshasaParts(now).month+"-"+kinshasaParts(now).day;
  if(!c || c.revoked) return "RÉVOQUÉE";
  if(!c.approved) return "EN ATTENTE DE VALIDATION";
  if(c.type==="VISITEUR" && (!c.validUntil || now.getTime()>Date.parse(c.validUntil))) return "EXPIRÉE";
  if(c.type!=="VISITEUR" && (!c.expiry || day>c.expiry)) return "EXPIRÉE";
  if(c.issued && day<c.issued) return "PAS ENCORE VALIDE";
  return "VALIDE";
}
export default async (req) => {
  try {
    const url=new URL(req.url), path=url.pathname.replace(/^\/\.netlify\/functions\/api\/?/, "");
    const db=await store();
    if(req.method==="GET" && path==="health") return json({ok:true,service:"PORT DE KINSHASA API"});
    // Assistant de première installation : le compte peut être créé une seule fois.
    if(req.method==="GET" && path==="admin-setup-status") {
      const existing=await db.get("admin",{type:"json"});
      return json({setupRequired:!existing});
    }
    if(req.method==="POST" && path==="admin-setup") {
      const {username,password,confirmPassword}=await req.json();
      if(await db.get("admin",{type:"json"})) return json({error:"Un administrateur existe déjà. La création initiale est désactivée."},409);
      const u=String(username||"").trim();
      if(!u || u.length<3 || u.length>60) return json({error:"L’identifiant doit contenir entre 3 et 60 caractères."},400);
      if(typeof password!=="string" || password.length<12) return json({error:"Le mot de passe doit contenir au moins 12 caractères."},400);
      if(password!==confirmPassword) return json({error:"Les deux mots de passe ne correspondent pas."},400);
      // Double vérification juste avant l'écriture pour éviter une deuxième création concurrente.
      if(await db.get("admin",{type:"json"})) return json({error:"Un administrateur existe déjà. Création refusée."},409);
      await db.setJSON("admin",{username:u,...hash(password),role:"admin",mustChangePassword:false,createdAt:new Date().toISOString()});
      return json({ok:true,message:"Administrateur créé. La création initiale est maintenant verrouillée."},201);
    }
    // Effacement contrôlé du seul enregistrement administrateur, protégé par un jeton temporaire.
    // Les cartes et les comptes agents restent intacts. Après cela, admin-setup ne peut créer qu'un compte.
    if(req.method==="POST" && path==="admin-clear-for-setup") {
      const {resetToken}=await req.json();
      const expected=process.env.ADMIN_RESET_TOKEN;
      if(!expected || expected.length<32) return json({error:"Définissez temporairement ADMIN_RESET_TOKEN (32 caractères minimum) dans Netlify, puis redéployez."},503);
      const supplied=String(resetToken||""); const a=Buffer.from(supplied), b=Buffer.from(expected);
      if(a.length!==b.length || !timingSafeEqual(a,b)) return json({error:"Jeton de récupération incorrect."},403);
      await db.delete("admin");
      return json({ok:true,message:"Ancien enregistrement administrateur supprimé. Les cartes et les comptes agents sont conservés. Créez maintenant le nouvel administrateur une seule fois."});
    }
    // Procédure de récupération protégée par un jeton temporaire défini dans Netlify.
    // Elle modifie uniquement le mot de passe de l'administrateur existant.
    if(req.method==="POST" && path==="admin-reset") {
      const {resetToken,newPassword}=await req.json();
      const expected=process.env.ADMIN_RESET_TOKEN;
      if(!expected || expected.length < 32) return json({error:"Récupération non configurée : définissez temporairement ADMIN_RESET_TOKEN (32 caractères minimum) dans Netlify."},503);
      const supplied=String(resetToken||"");
      const a=Buffer.from(supplied), b=Buffer.from(expected);
      if(a.length!==b.length || !timingSafeEqual(a,b)) return json({error:"Jeton de récupération incorrect."},403);
      if(typeof newPassword!=="string" || newPassword.length<12) return json({error:"Le nouveau mot de passe doit contenir au moins 12 caractères."},400);
      const existing=await db.get("admin",{type:"json"});
      if(!existing) return json({error:"Aucun compte administrateur existant trouvé. Aucune donnée n'a été modifiée."},404);
      await db.setJSON("admin",{...existing,...hash(newPassword),mustChangePassword:false});
      return json({ok:true,message:"Mot de passe administrateur réinitialisé. Supprimez maintenant ADMIN_RESET_TOKEN des variables Netlify et redéployez."});
    }
    if(req.method==="POST" && path==="login") {
      const {username,password}=await req.json();
      let admin=await db.get("admin",{type:"json"});
      // Aucun identifiant par défaut : l'administrateur doit être créé sur la page de première installation.
      if(!admin) return json({error:"Aucun administrateur configuré. Ouvrez /setup-admin.html pour effectuer la configuration initiale."},403);
      let user=null;
      if(username===admin.username && verify(password,admin)) user={username:admin.username,role:"admin",mustChangePassword:!!admin.mustChangePassword};
      else {
        const agents=await get("agents",[]);
        const entered=String(username||"").trim().toLowerCase();
        const matched=agents.find(x=>String(x.username||"").trim().toLowerCase()===entered);
        if(matched && matched.active===false) return json({error:"Ce compte agent est désactivé. Contactez l’administrateur."},403);
        const a=matched && verify(password,matched.password) ? matched : null;
        if(a) user={id:a.id,username:a.username,name:a.name,role:"agent",permissions:a.permissions||{}};
      }
      if(!user) return json({error:"Identifiants incorrects."},401);
      return json({ok:true,user},200,{ "set-cookie":makeCookie({user,exp:Date.now()+28800000})});
    }
    const s=await session(req);
    if(!s) return json({error:"Connexion requise."},401);
    const user=s.user;
    // Revalider le compte agent à chaque requête protégée : désactivation immédiate, même si une session était ouverte.
    if(user.role==="agent") {
      const currentAgents=await get("agents",[]);
      const currentAgent=currentAgents.find(a=>a.id===user.id || a.username===user.username);
      if(!currentAgent || currentAgent.active===false) {
        return json({error:"Compte agent supprimé ou désactivé. Contactez l’administrateur."},403,{"set-cookie":`${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`});
      }
    }

    if(path==="me" && req.method==="GET") { if(user.role==="agent"){const agents=await get("agents",[]);const a=agents.find(x=>x.id===user.id||x.username===user.username);return json({user:{...user,photo:a?.photo||""}})} return json({user}); }

    if(path==="scan" && req.method==="POST") {
      if(!has(user,"scan")) return json({error:"Droit de contrôle QR refusé. Demandez à l’administrateur d’autoriser cette fonction."},403);
      const {id}=await req.json();
      const token=String(id||"").trim();
      if(!token || token.length>200) return json({error:"QR code invalide."},400);
      const cards=await get("cards",[]);
      const c=cards.find(x=>x.id===token || x.number===token);
      const now=new Date();
      let state=cardValid(c,now);
      const local=kinshasaParts(now), minutes=Number(local.hour)*60+Number(local.minute);
      const afterClosing=minutes>16*60+30;
      const withinService=minutes>=8*60 && minutes<=16*60+30;
      const exception=c?.specialAuthorization;
      const exceptionActive=!!exception?.enabled && Date.parse(exception.startsAt)<=now.getTime() && Date.parse(exception.endsAt)>=now.getTime();
      if(state==="VALIDE" && !withinService) {
        if(afterClosing && exceptionActive) state="AUTORISÉ EXCEPTIONNELLEMENT";
        else if(afterClosing) state="HORS HORAIRES — AUTORISATION ADMINISTRATEUR REQUISE";
        else state="HORS HORAIRES — ACCÈS AVANT 08 H 00 REFUSÉ";
      }
      const allowed=!!c && (state==="VALIDE" || state==="AUTORISÉ EXCEPTIONNELLEMENT");
      const logs=await get("scanLogs",[]);
      logs.push({id:randomBytes(12).toString("hex"),cardId:c?.id||null,cardNumber:c?.number||token,cardType:c?.type||null,person:c?.person||null,checkedAt:now.toISOString(),checkedBy:user.username,checkerRole:user.role,result:allowed?"AUTORISÉ":"REFUSÉ",state});
      await put("scanLogs",logs.slice(-10000));
      return json({allowed,state,card:c?{number:c.number,type:c.type,person:c.person,company:c.company,job:c.job,reason:c.reason,photo:c.photo||"",issued:c.issued,expiry:c.expiry,validUntil:c.validUntil,specialAuthorization:c.specialAuthorization||null}:null,checkedAt:now.toISOString(),checkedBy:user.username});
    }
    if(req.method==="POST" && path==="logout") return json({ok:true},200,{"set-cookie":`${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`});
    if(req.method==="POST" && path==="change-password") {
      const {currentPassword,newPassword}=await req.json();
      if(!newPassword || String(newPassword).length<12) return json({error:"Choisissez un mot de passe d’au moins 12 caractères."},400);
      const admin=await db.get("admin",{type:"json"});
      if(user.role!=="admin" || !verify(currentPassword,admin)) return json({error:"Mot de passe actuel incorrect."},403);
      await db.setJSON("admin",{...admin,...hash(newPassword),mustChangePassword:false});
      return json({ok:true});
    }

    if(path==="agent-daily-report" && req.method==="GET") {
      if(user.role!=="agent" || (!has(user,"scan") && !has(user,"view"))) return json({error:"Rapport journalier non autorisé pour ce compte."},403);
      const now=new Date();
      const parts=kinshasaParts(now);
      const today=`${parts.year}-${parts.month}-${parts.day}`;
      const all=await get("scanLogs",[]);
      const logs=all.filter(x=>{
        if(!x.checkedAt) return false;
        const d=kinshasaParts(new Date(x.checkedAt));
        return `${d.year}-${d.month}-${d.day}`===today;
      }).sort((a,b)=>Date.parse(a.checkedAt)-Date.parse(b.checkedAt));
      return json({date:today,generatedAt:now.toISOString(),agent:user.username,logs,
        summary:{total:logs.length,allowed:logs.filter(x=>x.result==="AUTORISÉ").length,refused:logs.filter(x=>x.result!=="AUTORISÉ").length,
          entries:logs.filter(x=>x.result==="AUTORISÉ").length}});
    }
    if(path==="agent-scan-logs" && req.method==="GET") {
      if(user.role!=="agent" || (!has(user,"scan") && !has(user,"view"))) return json({error:"Historique non autorisé pour ce compte."},403);
      const logs=(await get("scanLogs",[])).slice().reverse().slice(0,200);
      return json({logs});
    }
    if(path==="scan-logs" && req.method==="GET") {
      if(user.role!=="admin") return json({error:"Journal de traçabilité réservé à l’administrateur."},403);
      return json({logs:(await get("scanLogs",[])).slice().reverse().slice(0,500)});
    }
    if(path==="cards" && req.method==="GET") {
      if(!has(user,"view")) return json({error:"Droit de consultation refusé."},403);
      return json({cards:await get("cards",[])});
    }
    if(path==="cards" && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut créer une carte."},403);
      const body=await req.json(), cards=await get("cards",[]);
      if(!["JOURNALIER","AGENT","VISITEUR"].includes(body.type)) return json({error:"Type de carte invalide."},400);
      if(!body.person || !body.company) return json({error:"Le nom et la société sont obligatoires."},400);
      if(body.type!=="VISITEUR" && (!body.issued || !body.expiry || body.expiry<body.issued)) return json({error:"Dates de validité incorrectes."},400);
      const year=new Date().getFullYear(), prefix=`DPK-${year}-`;
      const max=cards.filter(c=>c.number?.startsWith(prefix)).map(c=>Number(c.number.split("-").at(-1))||0).reduce((a,b)=>Math.max(a,b),0);
      const card={...body,id:randomBytes(16).toString("hex"),number:prefix+String(max+1).padStart(3,"0"),created:new Date().toISOString(),createdBy:user.username,approved:false,approvedBy:null,activatedAt:null,validUntil:null,revoked:false};
      cards.push(card); await put("cards",cards); return json({card},201);
    }
    const approval=path.match(/^cards\/([^/]+)\/approve$/);
    if(approval && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut valider une carte."},403);
      const cards=await get("cards",[]), c=cards.find(x=>x.id===approval[1]);
      if(!c) return json({error:"Carte introuvable."},404);
      if(c.revoked) return json({error:"Une carte révoquée ne peut pas être validée."},409);
      c.approved=true; c.approvedBy=user.username; c.activatedAt=new Date().toISOString();
      if(c.type==="VISITEUR") c.validUntil=new Date(Date.now()+24*60*60*1000).toISOString();
      await put("cards",cards); return json({ok:true,card:c});
    }
    const specialAuth=path.match(/^cards\/([^/]+)\/special-authorization$/);
    if(specialAuth && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut accorder une autorisation spéciale."},403);
      const {reason,endTime}=await req.json();
      const why=String(reason||"").trim(), end=String(endTime||"").trim();
      if(!why) return json({error:"Le motif de l’autorisation est obligatoire."},400);
      if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(end) || end<="16:30") return json({error:"L’heure de fin doit être postérieure à 16:30 (ex. 20:00)."},400);
      const cards=await get("cards",[]), c=cards.find(x=>x.id===specialAuth[1]);
      if(!c) return json({error:"Carte introuvable."},404);
      if(c.type!=="JOURNALIER") return json({error:"Cette dérogation est réservée aux cartes JOURNALIER dans cette version."},400);
      const now=new Date(), local=kinshasaParts(now), day=`${local.year}-${local.month}-${local.day}`;
      const status=cardValid(c,now);
      if(status!=="VALIDE") return json({error:`Autorisation impossible : la carte est ${status.toLowerCase()}.`},409);
      c.specialAuthorization={enabled:true,startsAt:new Date(`${day}T16:30:00+01:00`).toISOString(),endsAt:new Date(`${day}T${end}:00+01:00`).toISOString(),endTime:end,reason:why,authorizedBy:user.username,authorizedAt:now.toISOString()};
      await put("cards",cards);
      const audit=await get("adminLogs",[]); audit.push({action:"AUTORISATION_SPÉCIALE_CARTE",cardId:c.id,cardNumber:c.number,cardType:c.type,by:user.username,at:now.toISOString(),reason:why,endsAt:c.specialAuthorization.endsAt}); await put("adminLogs",audit.slice(-10000));
      return json({ok:true,card:c});
    }
    const revokeSpecial=path.match(/^cards\/([^/]+)\/special-authorization\/revoke$/);
    if(revokeSpecial && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut retirer une autorisation spéciale."},403);
      const cards=await get("cards",[]), c=cards.find(x=>x.id===revokeSpecial[1]);
      if(!c) return json({error:"Carte introuvable."},404);
      if(c.specialAuthorization) c.specialAuthorization={...c.specialAuthorization,enabled:false,revokedAt:new Date().toISOString(),revokedBy:user.username};
      await put("cards",cards);
      const audit=await get("adminLogs",[]); audit.push({action:"AUTORISATION_SPÉCIALE_RETIRÉE",cardId:c.id,cardNumber:c.number,by:user.username,at:new Date().toISOString()}); await put("adminLogs",audit.slice(-10000));
      return json({ok:true});
    }
    const m=path.match(/^cards\/([^/]+)\/(revoke|delete)$/);
    if(m && req.method==="POST") {
      const cards=await get("cards",[]), idx=cards.findIndex(c=>c.id===m[1]);
      if(idx<0) return json({error:"Carte introuvable."},404);
      if(m[2]==="revoke") { if(!has(user,"revoke")) return json({error:"Droit de révocation refusé."},403); cards[idx].revoked=true; await put("cards",cards); return json({ok:true}); }
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut supprimer une carte."},403);
      cards.splice(idx,1); await put("cards",cards); return json({ok:true});
    }
    if(path==="agents" && req.method==="GET") {
      if(user.role!=="admin") return json({error:"Réservé à l’administrateur."},403);
      return json({agents:(await get("agents",[])).map(({password,...a})=>({...a,active:a.active!==false}))});
    }
    if(path==="agents" && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Réservé à l’administrateur."},403);
      const b=await req.json(), agents=await get("agents",[]);
      if(!b.username || !b.name || !b.password || String(b.password).length<12) return json({error:"Nom, identifiant et mot de passe de 12 caractères minimum requis."},400);
      const username=String(b.username||"").trim();
      if(username.toLowerCase()==="ghost" || agents.some(a=>String(a.username||"").trim().toLowerCase()===username.toLowerCase())) return json({error:"Identifiant déjà utilisé."},409);
      const a={id:randomBytes(12).toString("hex"),name:String(b.name).trim(),username,password:hash(b.password),active:true,createdAt:new Date().toISOString(),createdBy:user.username,photo:typeof b.photo==="string" && b.photo.startsWith("data:image/") ? b.photo : "",permissions:{view:!!b.permissions?.view,create:!!b.permissions?.create,revoke:!!b.permissions?.revoke,scan:!!b.permissions?.scan}};
      agents.push(a); await put("agents",agents); return json({agent:{id:a.id,name:a.name,username:a.username,permissions:a.permissions}},201);
    }
    const agentAction=path.match(/^agents\/([^/]+)\/(disable|enable|delete)$/);
    if(agentAction && req.method==="POST") {
      if(user.role!=="admin") return json({error:"Seul l’administrateur peut modifier les comptes agents."},403);
      const [,agentId,action]=agentAction;
      const agents=await get("agents",[]);
      const idx=agents.findIndex(a=>a.id===agentId);
      if(idx<0) return json({error:"Compte agent introuvable."},404);
      const target=agents[idx];
      if(action==="disable" || action==="enable") {
        target.active=action==="enable";
        target.updatedAt=new Date().toISOString();
        target.updatedBy=user.username;
        await put("agents",agents);
        const audit=await get("adminLogs",[]);
        audit.push({action:target.active?"AGENT_RÉACTIVÉ":"AGENT_DÉSACTIVÉ",agentId:target.id,agentUsername:target.username,by:user.username,at:new Date().toISOString()});
        await put("adminLogs",audit.slice(-10000));
        return json({ok:true,active:target.active});
      }
      agents.splice(idx,1);
      await put("agents",agents);
      const audit=await get("adminLogs",[]);
      audit.push({action:"AGENT_SUPPRIMÉ",agentId:target.id,agentUsername:target.username,by:user.username,at:new Date().toISOString()});
      await put("adminLogs",audit.slice(-10000));
      return json({ok:true});
    }
    if(path==="admin-logs" && req.method==="GET") {
      if(user.role!=="admin") return json({error:"Journal réservé à l’administrateur."},403);
      return json({logs:(await get("adminLogs",[])).slice().reverse().slice(0,500)});
    }
    return json({error:"Route inconnue."},404);
  } catch(e) { return json({error:e.message||"Erreur serveur."},500); }
};
