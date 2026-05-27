"use client";

import { useState } from "react";

interface DiffLine {
  type: "added" | "removed" | "unchanged";
  content: string;
  lineNumber?: number;
}

interface DiffFile {
  path: string;
  oldContent: string;
  newContent: string;
  diffLines: DiffLine[];
}

interface DiffViewerProps {
  files: DiffFile[];
}

export function DiffViewer({ files }: DiffViewerProps) {
  const [activeFileIndex, setActiveFileIndex] = useState(0);
  const [showUnchanged, setShowUnchanged] = useState(true);

  const activeFile = files[activeFileIndex];

  const toggleUnchanged = () => {
    setShowUnchanged(!showUnchanged);
  };

  const renderDiffLine = (line: DiffLine, index: number) => {
    if (!showUnchanged && line.type === "unchanged") {
      return null;
    }

    let className = "px-4 py-1 text-sm font-mono";
    
    if (line.type === "added") {
      className += " bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border-l-2 border-green-500";
    } else if (line.type === "removed") {
      className += " bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border-l-2 border-red-500 line-through";
    } else {
      className += " bg-gray-50 dark:bg-gray-800/50 text-gray-800 dark:text-gray-200";
    }

    return (
      <div key={index} className={className}>
        <span className="text-gray-500 dark:text-gray-400 w-10 inline-block text-right mr-2 select-none">
          {line.lineNumber}
        </span>
        <span className="whitespace-pre-wrap">{line.content}</span>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full">
      {/* File Tabs */}
      <div className="flex overflow-x-auto border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        {files.map((file, index) => (
          <button
            key={index}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeFileIndex === index
                ? "border-blue-500 text-blue-600 dark:text-blue-400"
                : "border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
            }`}
            onClick={() => setActiveFileIndex(index)}
          >
            {file.path}
          </button>
        ))}
      </div>

      {/* Diff Content */}
      <div className="flex-1 overflow-auto">
        <div className="flex">
          {/* Old Content */}
          <div className="w-1/2 border-r border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
            <div className="px-4 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
              Original
            </div>
            <div className="text-sm">
              {activeFile.diffLines
                .filter(line => line.type === "removed" || line.type === "unchanged")
                .map((line, index) => renderDiffLine(line, index))}
            </div>
          </div>

          {/* New Content */}
          <div className="w-1/2 bg-white dark:bg-gray-900">
            <div className="px-4 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
              Fixed
            </div>
            <div className="text-sm">
              {activeFile.diffLines
                .filter(line => line.type === "added" || line.type === "unchanged")
                .map((line, index) => renderDiffLine(line, index))}
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between p-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        <div className="flex items-center">
          <input
            type="checkbox"
            id="show-unchanged"
            checked={showUnchanged}
            onChange={toggleUnchanged}
            className="mr-2"
          />
          <label htmlFor="show-unchanged" className="text-sm text-gray-700 dark:text-gray-300">
            Show unchanged lines
          </label>
        </div>
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {activeFile.diffLines.filter(l => l.type === "added").length} additions, 
          {activeFile.diffLines.filter(l => l.type === "removed").length} deletions
        </div>
      </div>
    </div>
  );
}