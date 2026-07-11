export interface TermRule {
  keyword: string;
  professional: string;
}

export const defaultTerms: TermRule[] = [
  { keyword: "赚钱", professional: "收益优化" },
  { keyword: "股票", professional: "金融资产" },
  { keyword: "写程序", professional: "软件系统开发" },
  { keyword: "看数据", professional: "数据分析" }
];

export function convertToProfessional(text: string): string {
  let result = text;
  for (const item of defaultTerms) {
    result = result.replaceAll(item.keyword, item.professional);
  }
  return result;
}
