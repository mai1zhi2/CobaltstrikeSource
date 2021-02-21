package org.apache.batik.svggen;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsConfiguration;
import java.awt.Image;
import java.awt.Paint;
import java.awt.Shape;
import java.awt.Stroke;
import java.awt.font.GlyphVector;
import java.awt.font.TextAttribute;
import java.awt.font.TextLayout;
import java.awt.geom.AffineTransform;
import java.awt.geom.NoninvertibleTransformException;
import java.awt.image.BufferedImage;
import java.awt.image.BufferedImageOp;
import java.awt.image.ImageObserver;
import java.awt.image.RenderedImage;
import java.awt.image.renderable.RenderableImage;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.AttributedCharacterIterator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.batik.ext.awt.g2d.AbstractGraphics2D;
import org.apache.batik.ext.awt.g2d.GraphicContext;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SVGGraphics2D extends AbstractGraphics2D implements Cloneable, SVGSyntax, ErrorConstants {
   public static final String DEFAULT_XML_ENCODING = "ISO-8859-1";
   public static final int DEFAULT_MAX_GC_OVERRIDES = 3;
   protected DOMTreeManager domTreeManager;
   protected DOMGroupManager domGroupManager;
   protected SVGGeneratorContext generatorCtx;
   protected SVGShape shapeConverter;
   protected Dimension svgCanvasSize;
   protected Graphics2D fmg;
   protected Set unsupportedAttributes;

   public final Dimension getSVGCanvasSize() {
      return this.svgCanvasSize;
   }

   public final void setSVGCanvasSize(Dimension var1) {
      this.svgCanvasSize = new Dimension(var1);
   }

   public final SVGGeneratorContext getGeneratorContext() {
      return this.generatorCtx;
   }

   public final SVGShape getShapeConverter() {
      return this.shapeConverter;
   }

   public final DOMTreeManager getDOMTreeManager() {
      return this.domTreeManager;
   }

   protected final void setDOMTreeManager(DOMTreeManager var1) {
      this.domTreeManager = var1;
      this.generatorCtx.genericImageHandler.setDOMTreeManager(this.domTreeManager);
   }

   protected final DOMGroupManager getDOMGroupManager() {
      return this.domGroupManager;
   }

   protected final void setDOMGroupManager(DOMGroupManager var1) {
      this.domGroupManager = var1;
   }

   public final Document getDOMFactory() {
      return this.generatorCtx.domFactory;
   }

   public final ImageHandler getImageHandler() {
      return this.generatorCtx.imageHandler;
   }

   public final GenericImageHandler getGenericImageHandler() {
      return this.generatorCtx.genericImageHandler;
   }

   public final ExtensionHandler getExtensionHandler() {
      return this.generatorCtx.extensionHandler;
   }

   public final void setExtensionHandler(ExtensionHandler var1) {
      this.generatorCtx.setExtensionHandler(var1);
   }

   public SVGGraphics2D(Document var1) {
      this(SVGGeneratorContext.createDefault(var1), false);
   }

   public SVGGraphics2D(Document var1, ImageHandler var2, ExtensionHandler var3, boolean var4) {
      this(buildSVGGeneratorContext(var1, var2, var3), var4);
   }

   public static SVGGeneratorContext buildSVGGeneratorContext(Document var0, ImageHandler var1, ExtensionHandler var2) {
      SVGGeneratorContext var3 = new SVGGeneratorContext(var0);
      var3.setIDGenerator(new SVGIDGenerator());
      var3.setExtensionHandler(var2);
      var3.setImageHandler(var1);
      var3.setStyleHandler(new DefaultStyleHandler());
      var3.setComment("Generated by the Batik Graphics2D SVG Generator");
      var3.setErrorHandler(new DefaultErrorHandler());
      return var3;
   }

   public SVGGraphics2D(SVGGeneratorContext var1, boolean var2) {
      super(var2);
      BufferedImage var3 = new BufferedImage(1, 1, 2);
      this.fmg = var3.createGraphics();
      this.unsupportedAttributes = new HashSet();
      this.unsupportedAttributes.add(TextAttribute.BACKGROUND);
      this.unsupportedAttributes.add(TextAttribute.BIDI_EMBEDDING);
      this.unsupportedAttributes.add(TextAttribute.CHAR_REPLACEMENT);
      this.unsupportedAttributes.add(TextAttribute.JUSTIFICATION);
      this.unsupportedAttributes.add(TextAttribute.RUN_DIRECTION);
      this.unsupportedAttributes.add(TextAttribute.SUPERSCRIPT);
      this.unsupportedAttributes.add(TextAttribute.SWAP_COLORS);
      this.unsupportedAttributes.add(TextAttribute.TRANSFORM);
      this.unsupportedAttributes.add(TextAttribute.WIDTH);
      if (var1 == null) {
         throw new SVGGraphics2DRuntimeException("generatorContext should not be null");
      } else {
         this.setGeneratorContext(var1);
      }
   }

   protected void setGeneratorContext(SVGGeneratorContext var1) {
      this.generatorCtx = var1;
      this.gc = new GraphicContext(new AffineTransform());
      SVGGeneratorContext.GraphicContextDefaults var2 = var1.getGraphicContextDefaults();
      if (var2 != null) {
         if (var2.getPaint() != null) {
            this.gc.setPaint(var2.getPaint());
         }

         if (var2.getStroke() != null) {
            this.gc.setStroke(var2.getStroke());
         }

         if (var2.getComposite() != null) {
            this.gc.setComposite(var2.getComposite());
         }

         if (var2.getClip() != null) {
            this.gc.setClip(var2.getClip());
         }

         if (var2.getRenderingHints() != null) {
            this.gc.setRenderingHints(var2.getRenderingHints());
         }

         if (var2.getFont() != null) {
            this.gc.setFont(var2.getFont());
         }

         if (var2.getBackground() != null) {
            this.gc.setBackground(var2.getBackground());
         }
      }

      this.shapeConverter = new SVGShape(var1);
      this.domTreeManager = new DOMTreeManager(this.gc, var1, 3);
      this.domGroupManager = new DOMGroupManager(this.gc, this.domTreeManager);
      this.domTreeManager.addGroupManager(this.domGroupManager);
      var1.genericImageHandler.setDOMTreeManager(this.domTreeManager);
   }

   public SVGGraphics2D(SVGGraphics2D var1) {
      super(var1);
      BufferedImage var2 = new BufferedImage(1, 1, 2);
      this.fmg = var2.createGraphics();
      this.unsupportedAttributes = new HashSet();
      this.unsupportedAttributes.add(TextAttribute.BACKGROUND);
      this.unsupportedAttributes.add(TextAttribute.BIDI_EMBEDDING);
      this.unsupportedAttributes.add(TextAttribute.CHAR_REPLACEMENT);
      this.unsupportedAttributes.add(TextAttribute.JUSTIFICATION);
      this.unsupportedAttributes.add(TextAttribute.RUN_DIRECTION);
      this.unsupportedAttributes.add(TextAttribute.SUPERSCRIPT);
      this.unsupportedAttributes.add(TextAttribute.SWAP_COLORS);
      this.unsupportedAttributes.add(TextAttribute.TRANSFORM);
      this.unsupportedAttributes.add(TextAttribute.WIDTH);
      this.generatorCtx = var1.generatorCtx;
      this.gc.validateTransformStack();
      this.shapeConverter = var1.shapeConverter;
      this.domTreeManager = var1.domTreeManager;
      this.domGroupManager = new DOMGroupManager(this.gc, this.domTreeManager);
      this.domTreeManager.addGroupManager(this.domGroupManager);
   }

   public void stream(String var1) throws SVGGraphics2DIOException {
      this.stream(var1, false);
   }

   public void stream(String var1, boolean var2) throws SVGGraphics2DIOException {
      try {
         OutputStreamWriter var3 = new OutputStreamWriter(new FileOutputStream(var1), "ISO-8859-1");
         this.stream((Writer)var3, var2);
         var3.flush();
         var3.close();
      } catch (SVGGraphics2DIOException var4) {
         throw var4;
      } catch (IOException var5) {
         this.generatorCtx.errorHandler.handleError(new SVGGraphics2DIOException(var5));
      }

   }

   public void stream(Writer var1) throws SVGGraphics2DIOException {
      this.stream(var1, false);
   }

   public void stream(Writer var1, boolean var2, boolean var3) throws SVGGraphics2DIOException {
      Element var4 = this.getRoot();
      this.stream(var4, var1, var2, var3);
   }

   public void stream(Writer var1, boolean var2) throws SVGGraphics2DIOException {
      Element var3 = this.getRoot();
      this.stream(var3, var1, var2, false);
   }

   public void stream(Element var1, Writer var2) throws SVGGraphics2DIOException {
      this.stream(var1, var2, false, false);
   }

   public void stream(Element var1, Writer var2, boolean var3, boolean var4) throws SVGGraphics2DIOException {
      Node var5 = var1.getParentNode();
      Node var6 = var1.getNextSibling();

      try {
         var1.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "http://www.w3.org/2000/svg");
         var1.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xlink", "http://www.w3.org/1999/xlink");
         DocumentFragment var7 = var1.getOwnerDocument().createDocumentFragment();
         var7.appendChild(var1);
         if (var3) {
            SVGCSSStyler.style(var7);
         }

         XmlWriter.writeXml((Node)var7, (Writer)var2, var4);
         var2.flush();
      } catch (SVGGraphics2DIOException var13) {
         this.generatorCtx.errorHandler.handleError(var13);
      } catch (IOException var14) {
         this.generatorCtx.errorHandler.handleError(new SVGGraphics2DIOException(var14));
      } finally {
         if (var5 != null) {
            if (var6 == null) {
               var5.appendChild(var1);
            } else {
               var5.insertBefore(var1, var6);
            }
         }

      }

   }

   public List getDefinitionSet() {
      return this.domTreeManager.getDefinitionSet();
   }

   public Element getTopLevelGroup() {
      return this.getTopLevelGroup(true);
   }

   public Element getTopLevelGroup(boolean var1) {
      return this.domTreeManager.getTopLevelGroup(var1);
   }

   public void setTopLevelGroup(Element var1) {
      this.domTreeManager.setTopLevelGroup(var1);
   }

   public Element getRoot() {
      return this.getRoot((Element)null);
   }

   public Element getRoot(Element var1) {
      var1 = this.domTreeManager.getRoot(var1);
      if (this.svgCanvasSize != null) {
         var1.setAttributeNS((String)null, "width", String.valueOf(this.svgCanvasSize.width));
         var1.setAttributeNS((String)null, "height", String.valueOf(this.svgCanvasSize.height));
      }

      return var1;
   }

   public Graphics create() {
      return new SVGGraphics2D(this);
   }

   public void setXORMode(Color var1) {
      this.generatorCtx.errorHandler.handleError(new SVGGraphics2DRuntimeException("XOR Mode is not supported by Graphics2D SVG Generator"));
   }

   public FontMetrics getFontMetrics(Font var1) {
      return this.fmg.getFontMetrics(var1);
   }

   public void copyArea(int var1, int var2, int var3, int var4, int var5, int var6) {
   }

   public boolean drawImage(Image var1, int var2, int var3, ImageObserver var4) {
      Element var5 = this.getGenericImageHandler().createElement(this.getGeneratorContext());
      AffineTransform var6 = this.getGenericImageHandler().handleImage(var1, var5, var2, var3, var1.getWidth((ImageObserver)null), var1.getHeight((ImageObserver)null), this.getGeneratorContext());
      if (var6 == null) {
         this.domGroupManager.addElement(var5);
      } else {
         AffineTransform var7 = null;

         try {
            var7 = var6.createInverse();
         } catch (NoninvertibleTransformException var9) {
            throw new SVGGraphics2DRuntimeException("unexpected exception");
         }

         this.gc.transform(var6);
         this.domGroupManager.addElement(var5);
         this.gc.transform(var7);
      }

      return true;
   }

   public boolean drawImage(Image var1, int var2, int var3, int var4, int var5, ImageObserver var6) {
      Element var7 = this.getGenericImageHandler().createElement(this.getGeneratorContext());
      AffineTransform var8 = this.getGenericImageHandler().handleImage(var1, var7, var2, var3, var4, var5, this.getGeneratorContext());
      if (var8 == null) {
         this.domGroupManager.addElement(var7);
      } else {
         AffineTransform var9 = null;

         try {
            var9 = var8.createInverse();
         } catch (NoninvertibleTransformException var11) {
            throw new SVGGraphics2DRuntimeException("unexpected exception");
         }

         this.gc.transform(var8);
         this.domGroupManager.addElement(var7);
         this.gc.transform(var9);
      }

      return true;
   }

   public void dispose() {
      this.domTreeManager.removeGroupManager(this.domGroupManager);
   }

   public void draw(Shape var1) {
      Stroke var2 = this.gc.getStroke();
      if (var2 instanceof BasicStroke) {
         Element var3 = this.shapeConverter.toSVG(var1);
         if (var3 != null) {
            this.domGroupManager.addElement(var3, (short)1);
         }
      } else {
         Shape var4 = var2.createStrokedShape(var1);
         this.fill(var4);
      }

   }

   public boolean drawImage(Image var1, AffineTransform var2, ImageObserver var3) {
      boolean var4 = true;
      if (var2 == null) {
         var4 = this.drawImage(var1, 0, 0, (ImageObserver)null);
      } else {
         AffineTransform var5;
         if (var2.getDeterminant() != 0.0D) {
            var5 = null;

            try {
               var5 = var2.createInverse();
            } catch (NoninvertibleTransformException var7) {
               throw new SVGGraphics2DRuntimeException("unexpected exception");
            }

            this.gc.transform(var2);
            var4 = this.drawImage(var1, 0, 0, (ImageObserver)null);
            this.gc.transform(var5);
         } else {
            var5 = new AffineTransform(this.gc.getTransform());
            this.gc.transform(var2);
            var4 = this.drawImage(var1, 0, 0, (ImageObserver)null);
            this.gc.setTransform(var5);
         }
      }

      return var4;
   }

   public void drawImage(BufferedImage var1, BufferedImageOp var2, int var3, int var4) {
      var1 = var2.filter(var1, (BufferedImage)null);
      this.drawImage(var1, var3, var4, (ImageObserver)null);
   }

   public void drawRenderedImage(RenderedImage var1, AffineTransform var2) {
      Element var3 = this.getGenericImageHandler().createElement(this.getGeneratorContext());
      AffineTransform var4 = this.getGenericImageHandler().handleImage(var1, var3, var1.getMinX(), var1.getMinY(), var1.getWidth(), var1.getHeight(), this.getGeneratorContext());
      AffineTransform var5;
      if (var2 == null) {
         var5 = var4;
      } else if (var4 == null) {
         var5 = var2;
      } else {
         var5 = new AffineTransform(var2);
         var5.concatenate(var4);
      }

      if (var5 == null) {
         this.domGroupManager.addElement(var3);
      } else {
         AffineTransform var6;
         if (var5.getDeterminant() != 0.0D) {
            var6 = null;

            try {
               var6 = var5.createInverse();
            } catch (NoninvertibleTransformException var8) {
               throw new SVGGraphics2DRuntimeException("unexpected exception");
            }

            this.gc.transform(var5);
            this.domGroupManager.addElement(var3);
            this.gc.transform(var6);
         } else {
            var6 = new AffineTransform(this.gc.getTransform());
            this.gc.transform(var5);
            this.domGroupManager.addElement(var3);
            this.gc.setTransform(var6);
         }
      }

   }

   public void drawRenderableImage(RenderableImage var1, AffineTransform var2) {
      Element var3 = this.getGenericImageHandler().createElement(this.getGeneratorContext());
      AffineTransform var4 = this.getGenericImageHandler().handleImage(var1, var3, (double)var1.getMinX(), (double)var1.getMinY(), (double)var1.getWidth(), (double)var1.getHeight(), this.getGeneratorContext());
      AffineTransform var5;
      if (var2 == null) {
         var5 = var4;
      } else if (var4 == null) {
         var5 = var2;
      } else {
         var5 = new AffineTransform(var2);
         var5.concatenate(var4);
      }

      if (var5 == null) {
         this.domGroupManager.addElement(var3);
      } else {
         AffineTransform var6;
         if (var5.getDeterminant() != 0.0D) {
            var6 = null;

            try {
               var6 = var5.createInverse();
            } catch (NoninvertibleTransformException var8) {
               throw new SVGGraphics2DRuntimeException("unexpected exception");
            }

            this.gc.transform(var5);
            this.domGroupManager.addElement(var3);
            this.gc.transform(var6);
         } else {
            var6 = new AffineTransform(this.gc.getTransform());
            this.gc.transform(var5);
            this.domGroupManager.addElement(var3);
            this.gc.setTransform(var6);
         }
      }

   }

   public void drawString(String var1, float var2, float var3) {
      if (this.textAsShapes) {
         GlyphVector var7 = this.getFont().createGlyphVector(this.getFontRenderContext(), var1);
         this.drawGlyphVector(var7, var2, var3);
      } else {
         if (this.generatorCtx.svgFont) {
            this.domTreeManager.gcConverter.getFontConverter().recordFontUsage(var1, this.getFont());
         }

         AffineTransform var4 = this.getTransform();
         AffineTransform var5 = this.transformText(var2, var3);
         Element var6 = this.getDOMFactory().createElementNS("http://www.w3.org/2000/svg", "text");
         var6.setAttributeNS((String)null, "x", this.generatorCtx.doubleString((double)var2));
         var6.setAttributeNS((String)null, "y", this.generatorCtx.doubleString((double)var3));
         var6.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:space", "preserve");
         var6.appendChild(this.getDOMFactory().createTextNode(var1));
         this.domGroupManager.addElement(var6, (short)16);
         if (var5 != null) {
            this.setTransform(var4);
         }

      }
   }

   private AffineTransform transformText(float var1, float var2) {
      AffineTransform var3 = null;
      Font var4 = this.getFont();
      if (var4 != null) {
         var3 = var4.getTransform();
         if (var3 != null && !var3.isIdentity()) {
            AffineTransform var5 = new AffineTransform();
            var5.translate((double)var1, (double)var2);
            var5.concatenate(var3);
            var5.translate((double)(-var1), (double)(-var2));
            this.transform(var5);
         } else {
            var3 = null;
         }
      }

      return var3;
   }

   public void drawString(AttributedCharacterIterator var1, float var2, float var3) {
      if (!this.textAsShapes && !this.usesUnsupportedAttributes(var1)) {
         boolean var21 = false;
         if (var1.getRunLimit() < var1.getEndIndex()) {
            var21 = true;
         }

         Element var5 = this.getDOMFactory().createElementNS("http://www.w3.org/2000/svg", "text");
         var5.setAttributeNS((String)null, "x", this.generatorCtx.doubleString((double)var2));
         var5.setAttributeNS((String)null, "y", this.generatorCtx.doubleString((double)var3));
         var5.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:space", "preserve");
         Font var6 = this.getFont();
         Paint var7 = this.getPaint();
         char var8 = var1.first();
         this.setTextElementFill(var1);
         this.setTextFontAttributes(var1, var6);
         SVGGraphicContext var9 = this.domTreeManager.getGraphicContextConverter().toSVG(this.gc);
         this.domGroupManager.addElement(var5, (short)16);
         var9.getContext().put("stroke", "none");
         var9.getGroupContext().put("stroke", "none");
         boolean var10 = true;
         AffineTransform var11 = this.getTransform();

         for(AffineTransform var12 = null; var8 != '\uffff'; var8 = var1.next()) {
            Element var13 = var5;
            if (var21) {
               var13 = this.getDOMFactory().createElementNS("http://www.w3.org/2000/svg", "tspan");
               var5.appendChild(var13);
            }

            this.setTextElementFill(var1);
            boolean var14 = this.setTextFontAttributes(var1, var6);
            if (var14 || var10) {
               var12 = this.transformText(var2, var3);
               var10 = false;
            }

            int var15 = var1.getIndex();
            int var16 = var1.getRunLimit() - 1;
            StringBuffer var17 = new StringBuffer(var16 - var15);
            var17.append(var8);

            for(int var18 = var15; var18 < var16; ++var18) {
               var8 = var1.next();
               var17.append(var8);
            }

            String var22 = var17.toString();
            if (this.generatorCtx.isEmbeddedFontsOn()) {
               this.getDOMTreeManager().getGraphicContextConverter().getFontConverter().recordFontUsage(var22, this.getFont());
            }

            SVGGraphicContext var19 = this.domTreeManager.gcConverter.toSVG(this.gc);
            var19.getGroupContext().put("stroke", "none");
            SVGGraphicContext var20 = DOMGroupManager.processDeltaGC(var19, var9);
            this.setTextElementAttributes(var20, var1);
            this.domTreeManager.getStyleHandler().setStyle(var13, var20.getContext(), this.domTreeManager.getGeneratorContext());
            var13.appendChild(this.getDOMFactory().createTextNode(var22));
            if ((var14 || var10) && var12 != null) {
               this.setTransform(var11);
            }
         }

         this.setFont(var6);
         this.setPaint(var7);
      } else {
         TextLayout var4 = new TextLayout(var1, this.getFontRenderContext());
         var4.draw(this, var2, var3);
      }
   }

   public void fill(Shape var1) {
      Element var2 = this.shapeConverter.toSVG(var1);
      if (var2 != null) {
         this.domGroupManager.addElement(var2, (short)16);
      }

   }

   private boolean setTextFontAttributes(AttributedCharacterIterator var1, Font var2) {
      boolean var3 = false;
      if (var1.getAttribute(TextAttribute.FONT) != null || var1.getAttribute(TextAttribute.FAMILY) != null || var1.getAttribute(TextAttribute.WEIGHT) != null || var1.getAttribute(TextAttribute.POSTURE) != null || var1.getAttribute(TextAttribute.SIZE) != null) {
         Map var4 = var1.getAttributes();
         Font var5 = var2.deriveFont(var4);
         this.setFont(var5);
         var3 = true;
      }

      return var3;
   }

   private void setTextElementFill(AttributedCharacterIterator var1) {
      if (var1.getAttribute(TextAttribute.FOREGROUND) != null) {
         Color var2 = (Color)var1.getAttribute(TextAttribute.FOREGROUND);
         this.setPaint(var2);
      }

   }

   private void setTextElementAttributes(SVGGraphicContext var1, AttributedCharacterIterator var2) {
      String var3 = "";
      if (this.isUnderline(var2)) {
         var3 = var3 + "underline ";
      }

      if (this.isStrikeThrough(var2)) {
         var3 = var3 + "line-through ";
      }

      int var4 = var3.length();
      if (var4 != 0) {
         var1.getContext().put("text-decoration", var3.substring(0, var4 - 1));
      }

   }

   private boolean isBold(AttributedCharacterIterator var1) {
      Object var2 = var1.getAttribute(TextAttribute.WEIGHT);
      if (var2 == null) {
         return false;
      } else if (var2.equals(TextAttribute.WEIGHT_REGULAR)) {
         return false;
      } else if (var2.equals(TextAttribute.WEIGHT_DEMILIGHT)) {
         return false;
      } else if (var2.equals(TextAttribute.WEIGHT_EXTRA_LIGHT)) {
         return false;
      } else {
         return !var2.equals(TextAttribute.WEIGHT_LIGHT);
      }
   }

   private boolean isItalic(AttributedCharacterIterator var1) {
      Object var2 = var1.getAttribute(TextAttribute.POSTURE);
      return TextAttribute.POSTURE_OBLIQUE.equals(var2);
   }

   private boolean isUnderline(AttributedCharacterIterator var1) {
      Object var2 = var1.getAttribute(TextAttribute.UNDERLINE);
      return TextAttribute.UNDERLINE_ON.equals(var2);
   }

   private boolean isStrikeThrough(AttributedCharacterIterator var1) {
      Object var2 = var1.getAttribute(TextAttribute.STRIKETHROUGH);
      return TextAttribute.STRIKETHROUGH_ON.equals(var2);
   }

   public GraphicsConfiguration getDeviceConfiguration() {
      return null;
   }

   public void setUnsupportedAttributes(Set var1) {
      if (var1 == null) {
         this.unsupportedAttributes = null;
      } else {
         this.unsupportedAttributes = new HashSet(var1);
      }

   }

   public boolean usesUnsupportedAttributes(AttributedCharacterIterator var1) {
      if (this.unsupportedAttributes == null) {
         return false;
      } else {
         Set var2 = var1.getAllAttributeKeys();
         Iterator var3 = var2.iterator();

         do {
            if (!var3.hasNext()) {
               return false;
            }
         } while(!this.unsupportedAttributes.contains(var3.next()));

         return true;
      }
   }
}
