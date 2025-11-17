import React, { useState, useEffect } from 'react';
import { Tool } from '../types';

interface Props {
  selectedTool: Tool | null;
  onRun: (params: { target: string; args: string }) => void;
  running: boolean;
}

const ArgsPanel: React.FC<Props> = ({ selectedTool, onRun, running }) => {
  const [target, setTarget] = useState('');
  const [args, setArgs] = useState('');

  useEffect(() => {
    // Reset args when tool changes
    setTarget('');
    setArgs('');
  }, [selectedTool?.id]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTool) return;
    onRun({ target, args });
  };

  return (
    <div className="panel panel-right">
      <h3 className="panel-title">Arguments</h3>
      <div className="panel-scroll">
        {!selectedTool && <div>Select a tool on the left.</div>}
        {selectedTool && (
          <form onSubmit={handleSubmit} className="args-form">
            <div className="args-tool-name">{selectedTool.label}</div>
            {selectedTool.description && (
              <div className="args-tool-desc">{selectedTool.description}</div>
            )}

            {/* For now, treat everything as a "target + args" pattern. */}
            <label className="args-label">
              Target
              <input
                className="args-input"
                placeholder="192.168.0.0/24 or host.example.com"
                value={target}
                onChange={e => setTarget(e.target.value)}
              />
            </label>

            <label className="args-label">
              Extra arguments
              <input
                className="args-input"
                placeholder="-sCV -T4 -A -O --script discovery"
                value={args}
                onChange={e => setArgs(e.target.value)}
              />
            </label>

            <button
              type="submit"
              className="args-run-button"
              disabled={running || !target.trim()}
            >
              {running ? 'Running…' : 'Run'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

export default ArgsPanel;