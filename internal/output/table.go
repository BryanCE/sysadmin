// =============================================================================
// internal/output/table.go - Table formatting utilities
// =============================================================================
package output

import (
	"fmt"
	"io"
	"strings"
)

// Table represents a formatted table
type Table struct {
	headers []string
	rows    [][]string
	widths  []int
}

// NewTable creates a new table with the given headers
func NewTable(headers []string) *Table {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}

	return &Table{
		headers: headers,
		rows:    make([][]string, 0),
		widths:  widths,
	}
}

// AddRow adds a row to the table
func (t *Table) AddRow(row []string) {
	if len(row) != len(t.headers) {
		// Pad or truncate row to match header count
		newRow := make([]string, len(t.headers))
		copy(newRow, row)
		for i := len(row); i < len(t.headers); i++ {
			newRow[i] = ""
		}
		row = newRow
	}

	// Update column widths
	for i, cell := range row {
		if len(cell) > t.widths[i] {
			t.widths[i] = len(cell)
		}
	}

	t.rows = append(t.rows, row)
}

// Render renders the table to the writer
func (t *Table) Render(writer io.Writer) error {
	if len(t.headers) == 0 {
		return nil
	}

	// Calculate total width
	totalWidth := 0
	for _, width := range t.widths {
		totalWidth += width + 3 // +3 for " | "
	}
	totalWidth -= 3 // Remove last " | "

	// Print top border
	fmt.Fprintf(writer, "┌%s┐\n", strings.Repeat("─", totalWidth))

	// Print headers
	fmt.Fprint(writer, "│")
	for i, header := range t.headers {
		fmt.Fprintf(writer, " %-*s ", t.widths[i], header)
		if i < len(t.headers)-1 {
			fmt.Fprint(writer, "│")
		}
	}
	fmt.Fprintf(writer, "│\n")

	// Print header separator
	fmt.Fprintf(writer, "├%s┤\n", strings.Repeat("─", totalWidth))

	// Print rows
	for _, row := range t.rows {
		fmt.Fprint(writer, "│")
		for i, cell := range row {
			fmt.Fprintf(writer, " %-*s ", t.widths[i], cell)
			if i < len(row)-1 {
				fmt.Fprint(writer, "│")
			}
		}
		fmt.Fprintf(writer, "│\n")
	}

	// Print bottom border
	fmt.Fprintf(writer, "└%s┘\n", strings.Repeat("─", totalWidth))

	return nil
}