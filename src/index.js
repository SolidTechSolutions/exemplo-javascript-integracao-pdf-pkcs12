'use strict';

/**
 * [EN]    PAdES (PDF) signing example using a PKCS#12 certificate pre-imported into SolidSign cache.
 *         Start : node src/index.js  (or: npm start)
 *         Dev   : npx nodemon src/index.js  (or: npm run dev)
 *         Batch : POST http://localhost:8088/api/pdf/sign-pkcs12
 *         Form  : POST http://localhost:8088/api/pdf/sign/form
 *
 * [PT-BR] Exemplo de assinatura PAdES (PDF) com certificado PKCS#12 pré-importado na cache do SolidSign.
 *         Iniciar: node src/index.js  (ou: npm start)
 *         Dev    : npx nodemon src/index.js  (ou: npm run dev)
 *         Lote   : POST http://localhost:8088/api/pdf/sign-pkcs12
 *         Form   : POST http://localhost:8088/api/pdf/sign/form
 */

require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const PdfPkcs12Service = require('./service');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const service = new PdfPkcs12Service();

/**
 * [EN]    Batch endpoint — scans the configured input folder for .pdf files and signs them.
 * [PT-BR] Endpoint de lote — escaneia a pasta de entrada configurada por .pdf e assina em lote.
 */
app.post('/api/pdf/sign-pkcs12', async (req, res) => {
  const inputPath = process.env.SOLIDSIGN_BATCH_INPUT_PATH || '';
  const outputPath = process.env.SOLIDSIGN_BATCH_OUTPUT_PATH || '';
  const certId = process.env.SOLIDSIGN_CERT_ID || '';

  if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isDirectory()) {
    return res.status(400).json({ error: `Invalid input path: ${inputPath}` });
  }

  const pdfFiles = fs.readdirSync(inputPath)
    .filter(f => f.toLowerCase().endsWith('.pdf'))
    .map(f => path.join(inputPath, f));

  if (pdfFiles.length === 0) {
    return res.json({ message: `No PDF files found in ${inputPath}` });
  }

  console.info(`Found ${pdfFiles.length} files for local processing.`);
  const resultPath = await service.signPkcs12(pdfFiles, certId, outputPath);

  if (resultPath) return res.json({ message: `Processing completed! ZIP generated at: ${resultPath}` });
  return res.status(500).json({ error: 'Processing failed. Check logs.' });
});

/**
 * [EN]    Form signing endpoint — receives documents and all parameters from the request.
 *         signatureImage is optional; omit it if no visual signature image is needed.
 * [PT-BR] Endpoint de formulário — recebe documentos e todos os parâmetros da requisição.
 *         signatureImage é opcional; omita se não precisar de imagem de assinatura visual.
 */
app.post('/api/pdf/sign/form',
  upload.fields([{ name: 'document' }, { name: 'signatureImage' }]),
  async (req, res) => {
    const documents = req.files['document'] || [];
    const signatureImages = req.files['signatureImage'] || [];
    const {
      authorization, baseUrl, pfxCode, profile, hashAlgorithm, policyVersion,
      sigFieldMeasurementUnit, signatureFieldConfig, reason, location, contact,
      signatureFieldName, signatureTextConfig, mdpPermissionLevel,
      passwordsForDecryption, documentInfoMetadata, signatureQrCodeConfig,
    } = req.body;

    const zipBuffer = await service.signPkcs12Form({
      authorization, baseUrl, pfxCode, documents, signatureImages,
      profile, hashAlgorithm, policyVersion, sigFieldMeasurementUnit,
      signatureFieldConfig, reason, location, contact, signatureFieldName,
      signatureTextConfig, mdpPermissionLevel, passwordsForDecryption,
      documentInfoMetadata, signatureQrCodeConfig,
    });

    if (zipBuffer) {
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename=signed_pdf.zip');
      return res.send(zipBuffer);
    }
    return res.status(500).json({ error: 'Processing failed. Check logs.' });
  }
);

const PORT = process.env.PORT || 8088;
app.listen(PORT, () => console.info(`SolidSign PDF PKCS12 example running on port ${PORT}`));
