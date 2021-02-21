package common;

import dns.SleeveSecurity;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class SleeveUtil {
   protected SleeveSecurity crypto;

   public SleeveUtil() throws IOException {
      byte[] var1 = CommonUtils.readFile("resourcekey.bin");
      DataParser var2 = new DataParser(var1);
      var1 = var2.readBytes(16);
      var1 = var2.readBytes(16);
      CommonUtils.print_stat("keyd is: " + CommonUtils.toHex(CommonUtils.MD5(var1)) + " " + var1.length + "b");
      this.crypto = new SleeveSecurity();
      this.crypto.registerKey(var1);
      this.process();
   }

   public List walk() {
      LinkedList var1 = new LinkedList();
      File var2 = new File("resources/");
      String[] var3 = var2.list();
      Arrays.sort(var3);

      for(int var4 = 0; var4 < var3.length; ++var4) {
         if (!var3[var4].startsWith("artifact") && !var3[var4].startsWith("covertvpn") && !var3[var4].startsWith("dropper") && (var3[var4].endsWith(".exe") || var3[var4].endsWith(".dll") || var3[var4].endsWith(".o"))) {
            var1.add(var3[var4]);
         }
      }

      return var1;
   }

   public void processFile(String var1) {
      byte[] var2 = CommonUtils.readFile("resources/" + var1);
      byte[] var3 = this.crypto.encrypt(var2);
      CommonUtils.writeToFile(new File("bin/sleeve/" + var1), var3);
      CommonUtils.print_stat("Wrote '" + var1 + "' " + var3.length + " bytes");
      (new File("bin/resources/" + var1)).delete();
   }

   public void process() {
      (new File("bin/sleeve")).mkdirs();
      Iterator var1 = this.walk().iterator();

      while(var1.hasNext()) {
         this.processFile((String)var1.next());
      }

   }

   public static void main(String[] var0) {
      try {
         new SleeveUtil();
      } catch (Exception var2) {
         MudgeSanity.logException("SleeveUtil", var2, false);
      }

   }
}
