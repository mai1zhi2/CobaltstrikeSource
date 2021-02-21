package com.xmlmind.fo.converter.rtf;

import com.xmlmind.fo.font.FontUtil;
import java.io.PrintWriter;
import java.util.Hashtable;
import java.util.Vector;

public final class FontTable {
   public static final String FAMILY_ROMAN = "roman";
   public static final String FAMILY_SWISS = "swiss";
   public static final String FAMILY_MODERN = "modern";
   public static final String FAMILY_DECOR = "decor";
   public static final String FAMILY_SCRIPT = "script";
   public static final String FAMILY_TECH = "tech";
   private int defCharSet;
   private Vector fonts = new Vector();
   private Hashtable indexes = new Hashtable();

   public FontTable(int var1) {
      this.defCharSet = var1;
   }

   public int add(String var1) {
      return this.add(var1, this.defCharSet);
   }

   public int add(String var1, int var2) {
      return this.add(new FontTable.Font((String)null, var2, var1, (String[])null));
   }

   public int add(FontTable.Font var1) {
      this.fonts.addElement(var1);
      int var2 = this.fonts.size() - 1;
      Integer var3 = new Integer(var2);
      this.indexes.put(this.key(var1.name, var1.charSet), var3);
      if (var1.aliases != null) {
         for(int var4 = 0; var4 < var1.aliases.length; ++var4) {
            this.indexes.put(this.key(var1.aliases[var4], var1.charSet), var3);
         }
      }

      return var2;
   }

   private String key(String var1, int var2) {
      return var1.toLowerCase() + "," + var2;
   }

   public void print(PrintWriter var1) {
      var1.println("{\\fonttbl");
      int var2 = 0;

      for(int var3 = this.fonts.size(); var2 < var3; ++var2) {
         FontTable.Font var4 = (FontTable.Font)this.fonts.elementAt(var2);
         var1.print("\\f" + var2);
         var1.print("\\f" + var4.family);
         var1.print("\\fcharset" + var4.charSet);
         var1.println(" " + var4.name + ";");
      }

      var1.println("}");
   }

   public int index(String var1, int var2) {
      Integer var3 = (Integer)this.indexes.get(this.key(var1, var2));
      return var3 != null ? var3 : -1;
   }

   public int index(String var1) {
      return this.index(var1, this.defCharSet);
   }

   public FontTable.Font font(int var1) {
      return (FontTable.Font)this.fonts.elementAt(var1);
   }

   public String name(int var1) {
      return this.font(var1).name;
   }

   public static class Font implements Cloneable {
      public String family;
      public int charSet;
      public String name;
      public String[] aliases;

      public Font(String var1, int var2, String var3, String[] var4) {
         if (var1 == null) {
            switch(FontUtil.toGenericFamily(var3, false)) {
            case 1:
               var1 = "roman";
               break;
            case 2:
               var1 = "swiss";
               break;
            case 3:
               var1 = "modern";
               break;
            case 4:
               var1 = "decor";
               break;
            case 5:
               var1 = "script";
               break;
            default:
               var1 = "nil";
            }
         }

         this.family = var1;
         this.charSet = var2;
         this.name = var3;
         this.aliases = var4;
      }

      public FontTable.Font copy() {
         try {
            return (FontTable.Font)this.clone();
         } catch (CloneNotSupportedException var2) {
            return null;
         }
      }
   }
}
