#!/usr/bin/env python3

"""

------------------------------
IBM QRadar XML Section Remover
------------------------------

Functionality
-------------
• Opens an XML file.
• Automatically discovers all unique tag names that appear at the same level as the file’s root children (top-level sections).
• Allows targeting of tags anywhere within the XML tree through a toggleable option.
• Enables users to select tags for removal via checkboxes (pre-populated with common QRadar sections such as sensordevicecategory, sensordeviceprotocols, and sensordevicetype).
• Removes all occurrences of the selected tags and saves the modified XML file under a new name.

Notes
-----
• Tag matching is performed by *local name* to ensure that XML namespaces do not interfere.
• The application provides a report summarizing the number of sections removed per tag.
• Designed to efficiently handle large files through iterative processing.

Dependencies
------------
• Python standard library only: tkinter, xml.etree.ElementTree.

"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import xml.etree.ElementTree as ET
from collections import defaultdict

# --------------------- DPI / Window Size Helpers ---------------------

def set_fixed_initial_size(root, width=900, height=650):
    """Open window at the same pixel size on all OSes, centered; allow resizing."""
    # Improve DPI behavior on Windows so WxH is interpreted as real pixels
    try:
        if sys.platform.startswith("win"):
            from ctypes import windll
            # Per-monitor DPI aware (Windows 8.1+)
            windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    x = (sw - width) // 2
    y = (sh - height) // 2
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.resizable(True, True)

# --------------------- XML Helpers ---------------------

def localname(tag: str) -> str:
    """Return the local part of an XML tag (strip any namespace)."""
    if tag is None:
        return ""
    if tag.startswith("{"):
        # format: {namespace}local
        return tag.split("}", 1)[1]
    return tag

def build_parent_map(root: ET.Element):
    """Return a dict mapping child -> parent for the entire tree."""
    parent_map = {}
    for parent in root.iter():
        for child in list(parent):
            parent_map[child] = parent
    return parent_map

def discover_top_level_tags(root: ET.Element) -> set[str]:
    """Return unique local tag names among the root's direct children."""
    return {localname(child.tag) for child in list(root)}

def count_occurrences_any_depth(root: ET.Element, targets: set[str]) -> dict[str, int]:
    counts = defaultdict(int)
    for el in root.iter():
        ln = localname(el.tag)
        if ln in targets:
            counts[ln] += 1
    return counts

def remove_tags(root: ET.Element, targets: set[str], any_depth: bool = True) -> dict[str, int]:
    """Remove elements whose localname is in `targets`.
    If any_depth is False, only remove when the element is a direct child of root.
    Returns a dict of removed counts per tag.
    """
    removed = defaultdict(int)

    if any_depth:
        # Need a parent map to remove arbitrary nodes
        parent_map = build_parent_map(root)
        # Collect nodes to delete first to avoid mutating while iterating
        to_delete = []
        for el in list(root.iter()):
            if el is root:
                continue
            if localname(el.tag) in targets:
                to_delete.append(el)
        for el in to_delete:
            p = parent_map.get(el)
            if p is not None:
                ln = localname(el.tag)
                p.remove(el)
                removed[ln] += 1
    else:
        # Only immediate children of root
        for child in list(root):
            if localname(child.tag) in targets:
                ln = localname(child.tag)
                root.remove(child)
                removed[ln] += 1

    return removed

# --------------------- GUI Application ---------------------

class XMLSectionRemover(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master: tk.Tk = master
        self.pack(fill="both", expand=True)

        self.filepath: str | None = None
        self.tree: ET.ElementTree | None = None
        self.root_el: ET.Element | None = None

        self.checkbox_vars: dict[str, tk.BooleanVar] = {}
        self.any_depth_var = tk.BooleanVar(value=True)

        self._build_ui()

    # ---------- UI Construction ----------
    
    def _build_ui(self):
        self.master.title("IBM QRadar XML Section Remover")
        self.master.geometry("720x560")

        # Top toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(side="top", fill="x", padx=8, pady=8)
        ttk.Button(toolbar, text="Open XML", command=self.open_xml).pack(side="left")
        ttk.Button(toolbar, text="Reload", command=self.reload_xml).pack(side="left", padx=(6, 0))
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(toolbar, text="Select All", command=lambda: self.set_all(True)).pack(side="left")
        ttk.Button(toolbar, text="Select None", command=lambda: self.set_all(False)).pack(side="left", padx=(6, 0))
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(toolbar, text="Add Custom Tag", command=self.add_custom_tag_dialog).pack(side="left")

        # Any-depth toggle
        depth_box = ttk.Checkbutton(toolbar, text="Remove at Any Depth", variable=self.any_depth_var)
        depth_box.pack(side="right")

        # File info
        self.info_var = tk.StringVar(value="Open an XML file to begin.")
        info_lbl = ttk.Label(self, textvariable=self.info_var, justify="left")
        info_lbl.pack(anchor="w", padx=12, pady=(0, 4))

        # Scrollable checkbox area
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=12, pady=8)

        canvas = tk.Canvas(container, highlightthickness=0)
        vscroll = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.chk_frame = ttk.Frame(canvas)
        self.chk_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.chk_frame, anchor="nw")
        canvas.configure(yscrollcommand=vscroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        # Bottom bar
        bottom = ttk.Frame(self)
        bottom.pack(side="bottom", fill="x", padx=12, pady=12)
        self.status_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")
        ttk.Button(bottom, text="Remove and Save", command=self.save_modified).pack(side="right")

    # ---------- File Operations ----------
    
    def open_xml(self):
        path = filedialog.askopenfilename(
            title="Open XML",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        self._load_file(path)

    def reload_xml(self):
        if self.filepath:
            self._load_file(self.filepath)
        else:
            messagebox.showinfo("Reload", "No file loaded yet.")

    def _load_file(self, path: str):
        try:
            tree = ET.parse(path)
            root_el = tree.getroot()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse XML:\n{e}")
            return

        self.filepath = path
        self.tree = tree
        self.root_el = root_el

        top_tags = discover_top_level_tags(root_el)
        total_top = len(list(root_el))
        info = [
            f"File: {os.path.basename(path)}",
            f"Root Tag: <{localname(root_el.tag)}>",
            f"Top-Level Children: {total_top}",
            f"Unique Top-Level Tags Discovered: {len(top_tags)}",
        ]
        self.info_var.set("\n".join(info))

        self.populate_checkboxes(top_tags)
        self.status_var.set("")

    # ---------- Checkbox List ----------
    
    def populate_checkboxes(self, tags: set[str]):
        # Clear existing
        for w in list(self.chk_frame.children.values()):
            w.destroy()
        self.checkbox_vars.clear()
        for name in sorted(tags):
            var = tk.BooleanVar(value=False)  # start UNCHECKED
            cb = ttk.Checkbutton(self.chk_frame, text=name, variable=var)
            cb.pack(anchor="w", pady=2)
            self.checkbox_vars[name] = var

    def set_all(self, value: bool):
        for var in self.checkbox_vars.values():
            var.set(value)

    def add_custom_tag_dialog(self):
        win = tk.Toplevel(self)
        win.title("Add Custom Tag")
        win.transient(self.master)
        win.grab_set()

        ttk.Label(win, text="Enter a tag name (local name, without namespace):").pack(padx=12, pady=(12, 6))
        entry = ttk.Entry(win, width=40)
        entry.pack(padx=12, pady=6)
        entry.focus_set()

        def add_and_close(*_):
            name = entry.get().strip()
            if not name:
                return
            if name not in self.checkbox_vars:
                var = tk.BooleanVar(value=True)
                ttk.Checkbutton(self.chk_frame, text=name, variable=var).pack(anchor="w", pady=2)
                self.checkbox_vars[name] = var
            win.destroy()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=12, pady=(6, 12))
        ttk.Button(btns, text="Add", command=add_and_close).pack(side="right")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=(0, 6))
        win.bind("<Return>", add_and_close)

    # ---------- Removal & Save ----------
    
    def selected_tags(self) -> set[str]:
        return {name for name, var in self.checkbox_vars.items() if var.get()}

    def save_modified(self):
        if not self.tree or not self.root_el:
            messagebox.showinfo("No file", "Open an XML file first.")
            return

        tags = self.selected_tags()
        if not tags:
            messagebox.showinfo("Nothing selected", "Pick at least one tag to remove.")
            return

        # Work on a deep copy of the tree text to avoid altering the loaded tree
        # Simpler approach: re-parse the file to get a fresh tree
        try:
            fresh_tree = ET.parse(self.filepath)
            fresh_root = fresh_tree.getroot()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to re-parse XML before saving:\n{e}")
            return

        any_depth = self.any_depth_var.get()
        removed = remove_tags(fresh_root, tags, any_depth=any_depth)

        # Ask path
        base, ext = os.path.splitext(self.filepath or "output.xml")
        suggested = f"{base}-stripped.xml"
        out_path = filedialog.asksaveasfilename(
            title="Save modified XML as…",
            initialfile=os.path.basename(suggested),
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not out_path:
            return

        # Write out (preserve encoding if possible)
        try:
            # xml_declaration ensures a header, encoding defaults to 'utf-8'
            fresh_tree.write(out_path, encoding="utf-8", xml_declaration=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write file:\n{e}")
            return

        # Report: popup shows full details; status bar shows only "Saved: <file>"
        detail_lines = [f"Saved: {os.path.basename(out_path)}"]
        if removed:
            total_removed = sum(removed.values())
            detail_lines.append(f"Removed {total_removed} section(s):")
            for tag, cnt in sorted(removed.items()):
                detail_lines.append(f"  • {tag}: {cnt}")
        else:
            detail_lines.append("No matching sections were found to remove.")

        # Bottom status: only the filename
        self.status_var.set(f"Saved: {os.path.basename(out_path)}")

        # Popup: full report
        messagebox.showinfo("Done", "\n".join(detail_lines))

def main():
    root = tk.Tk()
    # Improve default ttk theme if available
    try:
        if sys.platform.startswith("win"):
            root.call("source", "sun-valley.tcl")  # if present, gracefully ignored otherwise
            root.call("set_theme", "light")
    except Exception:
        pass
    app = XMLSectionRemover(root)
    app.mainloop()
    
# --------------------- Application Entry ---------------------

def main():
    root = tk.Tk()
    set_fixed_initial_size(root, width=900, height=650)
    app = XMLSectionRemover(root)
    root.mainloop()

if __name__ == "__main__":
    main()
