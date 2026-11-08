// goast: emit a JSON representation of a Go source file's AST for
// the furqan-lint Go adapter. This binary is the substrate boundary
// between the Go ecosystem (go/ast, go/parser) and Python.
//
// Usage: goast PATH    # writes JSON to stdout, errors to stderr
//
// The JSON shape is defined in src/furqan_lint/go_adapter/translator.py.
// The translator places error in the right arm of UnionType per the
// Go convention that error is conventionally the last return value;
// see test_go_translator_emits_error_in_right_arm for the contract.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

type fileOut struct {
	Filename    string         `json:"filename"`
	Package     string         `json:"package"`
	PublicNames []string       `json:"public_names"`
	Functions   []functionOut  `json:"functions"`
}

type functionOut struct {
	Name            string      `json:"name"`
	Line            int         `json:"line"`
	Col             int         `json:"col"`
	Exported        bool        `json:"exported"`
	ReturnTypeNames []string    `json:"return_type_names"`
	Params          []paramOut  `json:"params"`
	BodyStatements  []stmtOut   `json:"body_statements"`
}

type paramOut struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type stmtOut struct {
	Type        string    `json:"type"`
	Line        int       `json:"line"`
	Body        []stmtOut `json:"body,omitempty"`
	ElseBody    []stmtOut `json:"else_body,omitempty"`
	LHS         []string  `json:"lhs,omitempty"`
	RHSCall     *callOut  `json:"rhs_call,omitempty"`
	Expressions []string  `json:"expressions,omitempty"`
}

type callOut struct {
	Name string `json:"name"`
	Line int    `json:"line"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goast PATH")
		os.Exit(2)
	}
	path := os.Args[1]
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	out := fileOut{
		Filename:    path,
		Package:     parsed.Name.Name,
		PublicNames: collectPublicNames(parsed),
		Functions:   collectFunctions(parsed, fset),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// receiverTypeName extracts the receiver type's name from a
// FuncDecl receiver field, handling six shapes (v0.8.3 added
// the two IndexListExpr cases for multi-param generics):
//
//   - *ast.Ident                                => "T"
//     (func (c T) Foo())
//   - *ast.StarExpr wrapping *ast.Ident         => "T"
//     (func (c *T) Foo())
//   - *ast.IndexExpr wrapping *ast.Ident        => "T"
//     (func (c T[U]) Foo())
//   - *ast.StarExpr wrapping *ast.IndexExpr     => "T"
//     (func (c *T[U]) Foo())
//   - *ast.IndexListExpr wrapping *ast.Ident    => "T"
//     (func (c T[K, V]) Foo())                  -- v0.8.3
//   - *ast.StarExpr wrapping *ast.IndexListExpr => "T"
//     (func (c *T[K, V]) Foo())                 -- v0.8.3
//
// Returns "" if the receiver shape is not one of the above
// (defensive; in practice every well-formed Go method
// receiver has one of the six shapes above). Empty receiver
// name causes collectPublicNames to fall back to the bare
// method name -- preserves the v0.8.1 behavior in unexpected
// cases rather than silently dropping the method.
func receiverTypeName(field *ast.Field) string {
	switch t := field.Type.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		switch inner := t.X.(type) {
		case *ast.Ident:
			return inner.Name
		case *ast.IndexExpr:
			if id, ok := inner.X.(*ast.Ident); ok {
				return id.Name
			}
		case *ast.IndexListExpr:
			if id, ok := inner.X.(*ast.Ident); ok {
				return id.Name
			}
		}
	case *ast.IndexExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func collectPublicNames(file *ast.File) []string {
	names := []string{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				name := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) > 0 {
					recv := receiverTypeName(d.Recv.List[0])
					if recv != "" {
						name = recv + "." + name
					}
				}
				names = append(names, name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							names = append(names, n.Name)
						}
					}
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						names = append(names, s.Name.Name)
					}
				}
			}
		}
	}
	return names
}

func collectFunctions(file *ast.File, fset *token.FileSet) []functionOut {
	out := []functionOut{}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		pos := fset.Position(fd.Pos())
		out = append(out, functionOut{
			Name:            fd.Name.Name,
			Line:            pos.Line,
			Col:             pos.Column - 1,
			Exported:        fd.Name.IsExported(),
			ReturnTypeNames: extractReturnTypes(fd.Type.Results),
			Params:          extractParams(fd.Type.Params),
			BodyStatements:  walkStatements(fd.Body, fset),
		})
	}
	return out
}

func extractReturnTypes(results *ast.FieldList) []string {
	out := []string{}
	if results == nil {
		return out
	}
	for _, field := range results.List {
		typeName := exprToString(field.Type)
		// A field with N names contributes N returns of the same type.
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			out = append(out, typeName)
		}
	}
	return out
}

func extractParams(params *ast.FieldList) []paramOut {
	out := []paramOut{}
	if params == nil {
		return out
	}
	for _, field := range params.List {
		typeName := exprToString(field.Type)
		if len(field.Names) == 0 {
			out = append(out, paramOut{Name: "", Type: typeName})
		} else {
			for _, name := range field.Names {
				out = append(out, paramOut{Name: name.Name, Type: typeName})
			}
		}
	}
	return out
}

func walkStatements(block *ast.BlockStmt, fset *token.FileSet) []stmtOut {
	out := []stmtOut{}
	if block == nil {
		return out
	}
	for _, stmt := range block.List {
		converted := convertStatement(stmt, fset)
		if converted != nil {
			out = append(out, *converted)
		}
	}
	return out
}

func convertStatement(stmt ast.Stmt, fset *token.FileSet) *stmtOut {
	pos := fset.Position(stmt.Pos())
	switch s := stmt.(type) {
	case *ast.IfStmt:
		bodyStmts := walkStatements(s.Body, fset)
		var elseStmts []stmtOut
		if s.Else != nil {
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				elseStmts = walkStatements(elseBlock, fset)
			} else if elseIf, ok := s.Else.(*ast.IfStmt); ok {
				inner := convertStatement(elseIf, fset)
				if inner != nil {
					elseStmts = []stmtOut{*inner}
				}
			}
		}
		return &stmtOut{
			Type:     "if",
			Line:     pos.Line,
			Body:     bodyStmts,
			ElseBody: elseStmts,
		}
	case *ast.ReturnStmt:
		exprs := []string{}
		for _, e := range s.Results {
			exprs = append(exprs, exprToString(e))
		}
		return &stmtOut{
			Type:        "return",
			Line:        pos.Line,
			Expressions: exprs,
		}
	case *ast.AssignStmt:
		lhs := []string{}
		for _, e := range s.Lhs {
			lhs = append(lhs, exprToString(e))
		}
		var rhsCall *callOut
		// Detect calls in RHS: f(...), pkg.f(...), recv.method(...)
		for _, e := range s.Rhs {
			if call, ok := e.(*ast.CallExpr); ok {
				rhsCall = &callOut{
					Name: exprToString(call.Fun),
					Line: fset.Position(call.Pos()).Line,
				}
				break
			}
		}
		return &stmtOut{
			Type:    "assign",
			Line:    pos.Line,
			LHS:     lhs,
			RHSCall: rhsCall,
		}
	case *ast.ExprStmt:
		// A bare call as a statement: f(); pkg.f(...). Surface as
		// assign with empty LHS so the translator can build CallRef.
		if call, ok := s.X.(*ast.CallExpr); ok {
			return &stmtOut{
				Type: "assign",
				Line: pos.Line,
				LHS:  []string{},
				RHSCall: &callOut{
					Name: exprToString(call.Fun),
					Line: fset.Position(call.Pos()).Line,
				},
			}
		}
		// Other expression statements: opaque.
		return &stmtOut{Type: "opaque", Line: pos.Line}
	default:
		// for / switch / select / defer / etc. -> opaque marker.
		return &stmtOut{Type: "opaque", Line: pos.Line}
	}
}

func exprToString(e ast.Expr) string {
	if e == nil {
		return ""
	}
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprToString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(v.X)
	case *ast.ArrayType:
		return "[]" + exprToString(v.Elt)
	case *ast.MapType:
		return "map[" + exprToString(v.Key) + "]" + exprToString(v.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	case *ast.IndexExpr:
		return exprToString(v.X) + "[" + exprToString(v.Index) + "]"
	case *ast.CallExpr:
		return exprToString(v.Fun) + "()"
	case *ast.BasicLit:
		return v.Value
	case *ast.UnaryExpr:
		return v.Op.String() + exprToString(v.X)
	case *ast.BinaryExpr:
		return exprToString(v.X) + v.Op.String() + exprToString(v.Y)
	case *ast.CompositeLit:
		return exprToString(v.Type) + "{}"
	case *ast.ParenExpr:
		return "(" + exprToString(v.X) + ")"
	case *ast.Ellipsis:
		return "..." + exprToString(v.Elt)
	default:
		// Unknown shape: render as type name.
		return strings.TrimPrefix(fmt.Sprintf("%T", e), "*ast.")
	}
}
