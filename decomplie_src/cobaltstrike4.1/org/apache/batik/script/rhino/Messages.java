package org.apache.batik.script.rhino;

import java.util.Locale;
import java.util.MissingResourceException;
import org.apache.batik.i18n.LocalizableSupport;

public class Messages {
   protected static final String RESOURCES = "org.apache.batik.script.rhino.resources.messages";
   protected static LocalizableSupport localizableSupport;
   // $FF: synthetic field
   static Class class$org$apache$batik$script$rhino$Messages;

   protected Messages() {
   }

   public static void setLocale(Locale var0) {
      localizableSupport.setLocale(var0);
   }

   public static Locale getLocale() {
      return localizableSupport.getLocale();
   }

   public static String formatMessage(String var0, Object[] var1) throws MissingResourceException {
      return localizableSupport.formatMessage(var0, var1);
   }

   public static String getString(String var0) throws MissingResourceException {
      return localizableSupport.getString(var0);
   }

   public static int getInteger(String var0) throws MissingResourceException {
      return localizableSupport.getInteger(var0);
   }

   public static int getCharacter(String var0) throws MissingResourceException {
      return localizableSupport.getCharacter(var0);
   }

   // $FF: synthetic method
   static Class class$(String var0) {
      try {
         return Class.forName(var0);
      } catch (ClassNotFoundException var2) {
         throw new NoClassDefFoundError(var2.getMessage());
      }
   }

   static {
      localizableSupport = new LocalizableSupport("org.apache.batik.script.rhino.resources.messages", (class$org$apache$batik$script$rhino$Messages == null ? (class$org$apache$batik$script$rhino$Messages = class$("org.apache.batik.script.rhino.Messages")) : class$org$apache$batik$script$rhino$Messages).getClassLoader());
   }
}
