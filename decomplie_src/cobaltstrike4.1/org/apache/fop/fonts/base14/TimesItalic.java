package org.apache.fop.fonts.base14;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.fop.fonts.Base14Font;
import org.apache.fop.fonts.CodePointMapping;
import org.apache.fop.fonts.FontType;

public class TimesItalic extends Base14Font {
   private static final String fontName = "Times-Italic";
   private static final String fullName = "Times Italic";
   private static final Set familyNames;
   private static final String encoding = "WinAnsiEncoding";
   private static final int capHeight = 653;
   private static final int xHeight = 441;
   private static final int ascender = 683;
   private static final int descender = -205;
   private static final int firstChar = 32;
   private static final int lastChar = 255;
   private static final int[] width = new int[256];
   private final CodePointMapping mapping;
   private static final Map kerning;
   private boolean enableKerning;

   public TimesItalic() {
      this(false);
   }

   public TimesItalic(boolean enableKerning) {
      this.mapping = CodePointMapping.getMapping("WinAnsiEncoding");
      this.enableKerning = false;
      this.enableKerning = enableKerning;
   }

   public String getEncodingName() {
      return "WinAnsiEncoding";
   }

   public String getFontName() {
      return "Times-Italic";
   }

   public String getEmbedFontName() {
      return this.getFontName();
   }

   public String getFullName() {
      return "Times Italic";
   }

   public Set getFamilyNames() {
      return familyNames;
   }

   public FontType getFontType() {
      return FontType.TYPE1;
   }

   public int getAscender(int size) {
      return size * 683;
   }

   public int getCapHeight(int size) {
      return size * 653;
   }

   public int getDescender(int size) {
      return size * -205;
   }

   public int getXHeight(int size) {
      return size * 441;
   }

   public int getFirstChar() {
      return 32;
   }

   public int getLastChar() {
      return 255;
   }

   public int getWidth(int i, int size) {
      return size * width[i];
   }

   public int[] getWidths() {
      int[] arr = new int[this.getLastChar() - this.getFirstChar() + 1];
      System.arraycopy(width, this.getFirstChar(), arr, 0, this.getLastChar() - this.getFirstChar() + 1);
      return arr;
   }

   public boolean hasKerningInfo() {
      return this.enableKerning;
   }

   public Map getKerningInfo() {
      return kerning;
   }

   public char mapChar(char c) {
      this.notifyMapOperation();
      char d = this.mapping.mapChar(c);
      if (d != 0) {
         return d;
      } else {
         this.warnMissingGlyph(c);
         return '#';
      }
   }

   public boolean hasChar(char c) {
      return this.mapping.mapChar(c) > 0;
   }

   static {
      width[65] = 611;
      width[198] = 889;
      width[193] = 611;
      width[194] = 611;
      width[196] = 611;
      width[192] = 611;
      width[197] = 611;
      width[195] = 611;
      width[66] = 611;
      width[67] = 667;
      width[199] = 667;
      width[68] = 722;
      width[69] = 611;
      width[201] = 611;
      width[202] = 611;
      width[203] = 611;
      width[200] = 611;
      width[208] = 722;
      width[128] = 500;
      width[70] = 611;
      width[71] = 722;
      width[72] = 722;
      width[73] = 333;
      width[205] = 333;
      width[206] = 333;
      width[207] = 333;
      width[204] = 333;
      width[74] = 444;
      width[75] = 667;
      width[76] = 556;
      width[77] = 833;
      width[78] = 667;
      width[209] = 667;
      width[79] = 722;
      width[140] = 944;
      width[211] = 722;
      width[212] = 722;
      width[214] = 722;
      width[210] = 722;
      width[216] = 722;
      width[213] = 722;
      width[80] = 611;
      width[81] = 722;
      width[82] = 611;
      width[83] = 500;
      width[138] = 500;
      width[84] = 556;
      width[222] = 611;
      width[85] = 722;
      width[218] = 722;
      width[219] = 722;
      width[220] = 722;
      width[217] = 722;
      width[86] = 611;
      width[87] = 833;
      width[88] = 611;
      width[89] = 556;
      width[221] = 556;
      width[159] = 556;
      width[90] = 556;
      width[142] = 556;
      width[97] = 500;
      width[225] = 500;
      width[226] = 500;
      width[180] = 333;
      width[228] = 500;
      width[230] = 667;
      width[224] = 500;
      width[38] = 778;
      width[229] = 500;
      width[94] = 422;
      width[126] = 541;
      width[42] = 500;
      width[64] = 920;
      width[227] = 500;
      width[98] = 500;
      width[92] = 278;
      width[124] = 275;
      width[123] = 400;
      width[125] = 400;
      width[91] = 389;
      width[93] = 389;
      width[166] = 275;
      width[149] = 350;
      width[99] = 444;
      width[231] = 444;
      width[184] = 333;
      width[162] = 500;
      width[136] = 333;
      width[58] = 333;
      width[44] = 250;
      width[169] = 760;
      width[164] = 500;
      width[100] = 500;
      width[134] = 500;
      width[135] = 500;
      width[176] = 400;
      width[168] = 333;
      width[247] = 675;
      width[36] = 500;
      width[101] = 444;
      width[233] = 444;
      width[234] = 444;
      width[235] = 444;
      width[232] = 444;
      width[56] = 500;
      width[133] = 889;
      width[151] = 889;
      width[150] = 500;
      width[61] = 675;
      width[240] = 500;
      width[33] = 333;
      width[161] = 389;
      width[102] = 278;
      width[53] = 500;
      width[131] = 500;
      width[52] = 500;
      width[103] = 500;
      width[223] = 500;
      width[96] = 333;
      width[62] = 675;
      width[171] = 500;
      width[187] = 500;
      width[139] = 333;
      width[155] = 333;
      width[104] = 500;
      width[45] = 333;
      width[105] = 278;
      width[237] = 278;
      width[238] = 278;
      width[239] = 278;
      width[236] = 278;
      width[106] = 278;
      width[107] = 444;
      width[108] = 278;
      width[60] = 675;
      width[172] = 675;
      width[109] = 722;
      width[175] = 333;
      width[181] = 500;
      width[215] = 675;
      width[110] = 500;
      width[57] = 500;
      width[241] = 500;
      width[35] = 500;
      width[111] = 500;
      width[243] = 500;
      width[244] = 500;
      width[246] = 500;
      width[156] = 667;
      width[242] = 500;
      width[49] = 500;
      width[189] = 750;
      width[188] = 750;
      width[185] = 300;
      width[170] = 276;
      width[186] = 310;
      width[248] = 500;
      width[245] = 500;
      width[112] = 500;
      width[182] = 523;
      width[40] = 333;
      width[41] = 333;
      width[37] = 833;
      width[46] = 250;
      width[183] = 250;
      width[137] = 1000;
      width[43] = 675;
      width[177] = 675;
      width[113] = 500;
      width[63] = 500;
      width[191] = 500;
      width[34] = 420;
      width[132] = 556;
      width[147] = 556;
      width[148] = 556;
      width[145] = 333;
      width[146] = 333;
      width[130] = 333;
      width[39] = 214;
      width[114] = 389;
      width[174] = 760;
      width[115] = 389;
      width[154] = 389;
      width[167] = 500;
      width[59] = 333;
      width[55] = 500;
      width[54] = 500;
      width[47] = 278;
      width[32] = 250;
      width[163] = 500;
      width[116] = 278;
      width[254] = 500;
      width[51] = 500;
      width[190] = 750;
      width[179] = 300;
      width[152] = 333;
      width[153] = 980;
      width[50] = 500;
      width[178] = 300;
      width[117] = 500;
      width[250] = 500;
      width[251] = 500;
      width[252] = 500;
      width[249] = 500;
      width[95] = 500;
      width[118] = 444;
      width[119] = 667;
      width[120] = 444;
      width[121] = 444;
      width[253] = 444;
      width[255] = 444;
      width[165] = 500;
      width[122] = 389;
      width[158] = 389;
      width[48] = 500;
      kerning = new HashMap();
      Integer first = new Integer(79);
      Map pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      Integer second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(84);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(88);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(107);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(112);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(80);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-80));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-80));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-90));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-135));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-80));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-135));
      first = new Integer(86);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-30));
      second = new Integer(58);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(71);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-129));
      second = new Integer(59);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(45);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-60));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-129));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-111));
      first = new Integer(118);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-74));
      first = new Integer(32);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(147);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-75));
      second = new Integer(84);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(145);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-35));
      first = new Integer(97);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(116);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(112);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(103);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(98);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(70);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-105));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-45));
      second = new Integer(114);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-75));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-115));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-135));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-75));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-135));
      first = new Integer(85);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-25));
      first = new Integer(100);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(100);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(83);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(122);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(68);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-35));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(146);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(100);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(32);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(114);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(116);
      ((Map)pairs).put(second, new Integer(-30));
      second = new Integer(108);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(115);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(58);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(32);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(119);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(104);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-74));
      first = new Integer(75);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-35));
      first = new Integer(82);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(85);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(84);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-18));
      first = new Integer(145);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(145);
      ((Map)pairs).put(second, new Integer(-111));
      first = new Integer(103);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(114);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(103);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(66);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(85);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(98);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(108);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(98);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(81);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(85);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(44);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(-140));
      second = new Integer(32);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(-140));
      first = new Integer(102);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(92));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(102);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(108);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(84);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-18));
      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(58);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(114);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(104);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(59);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(45);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-92));
      first = new Integer(121);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-55));
      first = new Integer(120);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(101);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-30));
      second = new Integer(112);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(103);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(98);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(120);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(99);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(107);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(104);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(108);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(87);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(58);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(104);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(59);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(45);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-60));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-70));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-92));
      first = new Integer(104);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(71);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(105);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(65);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-95));
      second = new Integer(67);
      ((Map)pairs).put(second, new Integer(-30));
      second = new Integer(112);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(81);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(71);
      ((Map)pairs).put(second, new Integer(-35));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-105));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(85);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(84);
      ((Map)pairs).put(second, new Integer(-37));
      first = new Integer(147);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(145);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(78);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-27));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(115);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(111);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(103);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(120);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(-10));
      first = new Integer(114);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-45));
      second = new Integer(100);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(107);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(114);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(99);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(112);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(103);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(108);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(113);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(45);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(109);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(116);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-111));
      second = new Integer(110);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(115);
      ((Map)pairs).put(second, new Integer(-10));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-37));
      first = new Integer(108);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(119);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(76);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(-37));
      second = new Integer(87);
      ((Map)pairs).put(second, new Integer(-55));
      second = new Integer(89);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(-30));
      second = new Integer(84);
      ((Map)pairs).put(second, new Integer(-20));
      second = new Integer(86);
      ((Map)pairs).put(second, new Integer(-55));
      first = new Integer(148);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(32);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(109);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      first = new Integer(89);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(45);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(105);
      ((Map)pairs).put(second, new Integer(-74));
      second = new Integer(79);
      ((Map)pairs).put(second, new Integer(-15));
      second = new Integer(58);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-50));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-92));
      second = new Integer(59);
      ((Map)pairs).put(second, new Integer(-65));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-92));
      first = new Integer(74);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(111);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(97);
      ((Map)pairs).put(second, new Integer(-35));
      second = new Integer(65);
      ((Map)pairs).put(second, new Integer(-40));
      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(-35));
      second = new Integer(46);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(101);
      ((Map)pairs).put(second, new Integer(-25));
      second = new Integer(44);
      ((Map)pairs).put(second, new Integer(-25));
      first = new Integer(46);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(148);
      ((Map)pairs).put(second, new Integer(-140));
      second = new Integer(146);
      ((Map)pairs).put(second, new Integer(-140));
      first = new Integer(110);
      pairs = (Map)kerning.get(first);
      if (pairs == null) {
         pairs = new HashMap();
         kerning.put(first, pairs);
      }

      second = new Integer(117);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(121);
      ((Map)pairs).put(second, new Integer(0));
      second = new Integer(118);
      ((Map)pairs).put(second, new Integer(-40));
      familyNames = new HashSet();
      familyNames.add("Times");
   }
}
