import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
const suffix=`baseline-${process.pid}-${Date.now()}`;
const tmp=`/tmp/${suffix}`, dbPath=`/home/node/.openclaw/${suffix}.sqlite`;
const forbidden=`/etc/${suffix}`;
if(process.getuid()===0) throw new Error('Unexpected UID 0');
if(fs.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token')) throw new Error('Unexpected API token');
try {
  fs.writeFileSync(tmp,'ok',{flag:'wx'});
  const db=new DatabaseSync(dbPath);
  try {db.exec("CREATE VIRTUAL TABLE probe USING fts5(body); INSERT INTO probe VALUES ('ok');");}
  finally {db.close();}
  let blocked=false;
  try {fs.writeFileSync(forbidden,'unexpected',{flag:'wx'});}
  catch(e) {if(!['EROFS','EACCES','EPERM'].includes(e.code)) throw e; blocked=true;}
  if(!blocked) {fs.unlinkSync(forbidden); throw new Error('System-root write succeeded');}
  console.log('PASS: non-root, no standard API token, writable tmp/SQLite FTS5, system write denied');
} finally {
  for(const p of [tmp,dbPath,dbPath+'-wal',dbPath+'-shm',dbPath+'-journal']) fs.rmSync(p,{force:true});
}
