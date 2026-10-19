import { start, stop } from "./gateway";

export default async function globalSetup() {
  await start();
  return async () => stop();
}
