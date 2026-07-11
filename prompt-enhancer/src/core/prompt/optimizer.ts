export type PromptMode = "simple" | "detail" | "creative" | "precision";

export function optimizePrompt(input: string, mode: PromptMode = "detail") {
  const templates = {
    simple: `Task:\n${input}`,
    detail: `Role:\nYou are an expert assistant.\n\nContext:\n${input}\n\nTask:\nProvide a structured solution.\n\nFormat:\nMarkdown\n\nConstraints:\nBe accurate and practical.`,
    creative: `You are a creative strategist.\nGoal:\n${input}\nGenerate innovative approaches.`,
    precision: `You are a senior engineer.\nTask:\n${input}\nProvide accurate implementation details and constraints.`
  };

  return templates[mode];
}
