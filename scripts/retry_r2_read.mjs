export async function retryR2Read(read, delayMs = 1000) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await read();
    } catch (error) {
      if (!error.message.startsWith("R2 read failed for ") || attempt === 2) throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs * (attempt + 1)));
    }
  }
}
