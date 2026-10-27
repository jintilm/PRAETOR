// Command samplestore 是样本库的命令行入口：入库 / 列表 / 校验。
//
// 为什么单独一个命令而不是加个工具：样本入库是**人工动作**（谁、什么时候、
// 因为什么把一份恶意样本收进来），不该让模型自己决定；而模型只需要 sha256，
// 之后用 `re_recipe` 的 `sha256:<hex>` 形态取用。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jintilm/praetor/internal/samplestore"
)

func main() {
	root := flag.String("dir", os.Getenv("PRAETOR_SAMPLE_DIR"), "样本库目录（默认取 PRAETOR_SAMPLE_DIR）")
	put := flag.String("put", "", "把该文件加密入库，打印 sha256")
	list := flag.Bool("ls", false, "列出索引（元数据，不含样本内容）")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "错误：未指定样本库目录（-dir 或 PRAETOR_SAMPLE_DIR）")
		os.Exit(2)
	}
	// 密钥从环境变量读；这里不提供任何"跳过加密"的开关。
	st, err := samplestore.Open(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}

	switch {
	case *put != "":
		ent, err := st.Put(*put, filepath.Base(*put))
		if err != nil {
			fmt.Fprintln(os.Stderr, "入库失败：", err)
			os.Exit(1)
		}
		fmt.Printf("%s\t%d bytes\t%s\nsha256:%s\n", ent.Name, ent.Size, ent.AddedAt.Format("2006-01-02 15:04"), ent.SHA256)
	case *list:
		ents, err := st.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, "读索引失败：", err)
			os.Exit(1)
		}
		for _, e := range ents {
			fmt.Printf("%s\t%8d\t%s\t%s\n", e.SHA256[:12], e.Size, e.AddedAt.Format("2006-01-02 15:04"), e.Name)
		}
		if len(ents) == 0 {
			fmt.Println("（样本库为空）")
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}
