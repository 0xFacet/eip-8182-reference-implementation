#!/usr/bin/env node

// Oracle Server

import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import createKeccakHash from 'keccak';

// Basic types
interface ForeignCallInfo {
  function: string;
  inputs: string[][];
}

interface ForeignCallResult {
  values: string[][];
}

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/", async (req, res) => {
  const { method, params, id } = req.body;
  
  if (method === "resolve_foreign_call") {
    const result = await handleForeignCall(params || []);
    res.json({ jsonrpc: "2.0", id, result });
  } else {
    res.json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
  }
});

async function handleForeignCall(params: any[]): Promise<ForeignCallResult> {
  const [callInfo] = params as [ForeignCallInfo];
  const { function: functionName, inputs } = callInfo;
  

  if (functionName === "getKeccak256") {
    return keccak256(inputs);
  } else {
    throw new Error(`Unknown function: ${functionName}`);
  }
}

function keccak256(inputs: any): ForeignCallResult {
  // Input format:
  // inputs[0] = length of input array as hex string
  // inputs[1] = array of hex strings
  // inputs[2] = message_size as hex string
  const inputArray = inputs[1] as string[];
  const messageSizeHex = inputs[2] as string;
  const messageSize = Number(BigInt('0x' + messageSizeHex));

  // Convert Field elements to bytes
  // Each Field element is a 64-character hex string, we need to extract the byte value
  const allBytes = inputArray.map((hexStr: string) => {
    return parseInt(hexStr, 16)
  });

  // Only hash message_size bytes
  const bytes = Buffer.from(allBytes.slice(0, messageSize));

  // Compute Keccak256 hash
  const hashResultBytes: string[] =
    Array.from(createKeccakHash('keccak256').update(bytes).digest())
         .map((b: number) => {
           // Return as Field element format (64-character hex string, no 0x prefix)
           return b.toString(16).padStart(64, '0');
         });
  return { values: [hashResultBytes] };
}


// Start server
const PORT = process.env.PORT || 8095;
app.listen(PORT, () => {
  console.log(`Oracle server running on port ${PORT}`);
});
