"""Read-only app metadata + synthetic View security-filter evaluation.
Never dispatches a touch/click, changes an auth result or reads key material.
"""
import json
import sys
import frida
from runtime_driver import make_script

SOURCE = r'''
rpc.exports = { inspect: function(expected) {
 return new Promise(function(resolve, reject) {
  Java.perform(function() { Java.scheduleOnMainThread(function() {
   try {
    const Thread=Java.use('android.app.ActivityThread');
    const app=Thread.currentApplication();
    if (!app || app.getPackageName().toString()!==expected) throw Error('identity');
    const View=Java.use('android.view.View'), Group=Java.use('android.view.ViewGroup');
    const Web=Java.use('android.webkit.WebView'), Text=Java.use('android.widget.TextView');
    const Motion=Java.use('android.view.MotionEvent');
    const Props=Java.use('android.view.MotionEvent$PointerProperties'), Coords=Java.use('android.view.MotionEvent$PointerCoords');
    function event(flags) {
      const prop=Props.$new(); prop.id.value=0; prop.toolType.value=1;
      const coords=Coords.$new(); coords.x.value=1; coords.y.value=1; coords.pressure.value=1; coords.size.value=1;
      return Motion.obtain.overload('long','long','int','int','[Landroid.view.MotionEvent$PointerProperties;','[Landroid.view.MotionEvent$PointerCoords;','int','int','float','float','int','int','int','int')
        .call(Motion, 0,0,0,1,Java.array('android.view.MotionEvent$PointerProperties',[prop]), Java.array('android.view.MotionEvent$PointerCoords',[coords]),0,0,1,1,0,0,0x1002,flags);
    }
    const screen={windows:0,secureWindows:0,passwordFields:0};
    const web={webviews:0,webviewJs:0};
    const taps={clickableViews:0,filterControls:0,filterRejectsFull:0,filterRejectsPartial:0};
    let keys={keystoreAliases:0,authRequiredKeys:0,unknownKeys:0};
    const activities=Thread.currentActivityThread().mActivities.value.values().toArray();
    let todo=[], visited=0, viewLimitReached=false, keyQueriesComplete=true;
    for(let i=0;i<activities.length;i++) {
      const record=Java.cast(activities[i], Java.use('android.app.ActivityThread$ActivityClientRecord'));
      const activity=record.activity.value;
      if (!activity || activity.isFinishing() || record.paused.value) continue;
      const window=activity.getWindow(); if(!window) continue;
      screen.windows++;
      if((window.getAttributes().flags.value & 0x2000)!==0) screen.secureWindows++;
      todo.push(window.getDecorView());
    }
    while(todo.length && visited++<2000) {
      const view=Java.cast(todo.pop(),View);
      if(!view.isShown()) continue;
      if(view.isClickable() && taps.clickableViews>=200) viewLimitReached=true;
      if(view.isClickable() && taps.clickableViews<200) {
        taps.clickableViews++;
        const a=event(0),b=event(1),c=event(2);
        try {
          // This asks the security predicate; it never dispatches the event.
          if(view.onFilterTouchEventForSecurity(a)) {
            taps.filterControls++;
            if(!view.onFilterTouchEventForSecurity(b)) taps.filterRejectsFull++;
            if(!view.onFilterTouchEventForSecurity(c)) taps.filterRejectsPartial++;
          }
        } finally {a.recycle();b.recycle();c.recycle();}
      }
      if(Text.class.isInstance(view)) {
        const input=Java.cast(view,Text).getInputType();
        if((input & 0xfff)===0x81 || (input & 0xfff)===0x91 || (input & 0xfff)===0xe1 || (input & 0xfff)===0x12) screen.passwordFields++;
      }
      if(Web.class.isInstance(view)) {web.webviews++; if(Java.cast(view,Web).getSettings().getJavaScriptEnabled()) web.webviewJs++;}
      if(Group.class.isInstance(view)) {
        const group=Java.cast(view,Group);
        if(group.getChildCount()+todo.length>4000) viewLimitReached=true;
        for(let i=0;i<group.getChildCount() && todo.length<4000;i++) todo.push(group.getChildAt(i));
      }
    }
    try {
      const store=Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');store.load.overload('java.security.KeyStore$LoadStoreParameter').call(store,null);
      const aliases=store.aliases(), infoClass=Java.use('android.security.keystore.KeyInfo').class;
      while(aliases.hasMoreElements() && keys.keystoreAliases<200) {
        const alias=Java.cast(aliases.nextElement(),Java.use('java.lang.String')).toString();keys.keystoreAliases++;
        try {
          // Opaque key handle only: never call getEncoded or cryptographic operations.
          const key=store.getKey(alias,null); if(!key){keys.unknownKeys++;continue;}
          let info;
          if(Java.use('javax.crypto.SecretKey').class.isInstance(key)) {
            const factory=Java.use('javax.crypto.SecretKeyFactory').getInstance(key.getAlgorithm(),'AndroidKeyStore');
            info=factory.getKeySpec(Java.cast(key,Java.use('javax.crypto.SecretKey')), infoClass);
          } else {
            const factory=Java.use('java.security.KeyFactory').getInstance(key.getAlgorithm(),'AndroidKeyStore');
            info=factory.getKeySpec(key,infoClass);
          }
          if(Java.cast(info,Java.use('android.security.keystore.KeyInfo')).isUserAuthenticationRequired()) keys.authRequiredKeys++;
        } catch(e) { keys.unknownKeys++;keyQueriesComplete=false; }
      }
      if(aliases.hasMoreElements()) keyQueriesComplete=false;
    } catch(e) { keys={};keyQueriesComplete=false; }
    resolve({bundle:expected,pid:Process.id,verified:true,screen:screen,webview:web,key_access:keys,tapjacking:taps,viewLimitReached:viewLimitReached||todo.length>0,keyQueriesComplete:keyQueriesComplete,instrumented:true,scope:'launch-filter-only'});
   } catch(e) {reject('observer unavailable');}
  });});
 });
}};
'''

def main():
    port, pid, package = sys.argv[1:4]
    if not port.isdigit() or not pid.isdigit():
        raise ValueError('invalid target')
    device = frida.get_device_manager().add_remote_device('127.0.0.1:' + port)
    session = device.attach(int(pid))
    try:
        script = make_script(session, SOURCE)
        script.load()
        print(json.dumps(script.exports_sync.inspect(package)))
    finally:
        session.detach()

if __name__ == '__main__':
    try: main()
    except Exception: print('{}')
