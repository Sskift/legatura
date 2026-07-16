import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { cloneJson } from "./canonical.mjs";

export function createChangeStore(repoPath) {
  const directory = path.join(repoPath, ".legatura", "runtime", "changes");

  return {
    async list() {
      let names;
      try {
        names = await readdir(directory);
      } catch (error) {
        if (error?.code === "ENOENT") return [];
        throw error;
      }
      const changes = [];
      for (const name of names.filter((entry) => entry.endsWith(".json")).sort()) {
        changes.push(await readChange(path.join(directory, name)));
      }
      return changes;
    },

    async get(id) {
      try {
        return await readChange(changePath(directory, id));
      } catch (error) {
        if (error?.code === "ENOENT") return undefined;
        throw error;
      }
    },

    async save(change) {
      await mkdir(directory, { recursive: true });
      const target = changePath(directory, change.id);
      const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(temporary, `${JSON.stringify(change, null, 2)}\n`, "utf8");
      await rename(temporary, target);
      return cloneJson(change);
    }
  };
}

async function readChange(filePath) {
  const text = await readFile(filePath, "utf8");
  try {
    return JSON.parse(text);
  } catch (error) {
    const problem = new Error(`Invalid Change record JSON in ${filePath}: ${error.message}`);
    problem.code = "CHANGE_RECORD_INVALID";
    problem.statusCode = 500;
    problem.details = { file: filePath };
    throw problem;
  }
}

function changePath(directory, id) {
  if (typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(id)) {
    const error = new Error("Change id contains unsupported characters.");
    error.code = "CHANGE_ID_INVALID";
    error.statusCode = 400;
    throw error;
  }
  return path.join(directory, `${id}.json`);
}
