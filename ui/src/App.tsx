import React, { useState } from 'react';
import Navbar from './components/Navbar';
import ToolPanel from './components/ToolPanel';
import GraphCanvas from './components/GraphCanvas';
import ArgsPanel from './components/ArgsPanel';
import ConsolePanel, { ConsoleState } from './components/ConsolePanel';
import { Tool, GraphData } from './types';
import { runNmapScan } from './api';

const App: React.FC = () => {
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [running, setRunning] = useState(false);
  const [consoleState, setConsoleState] = useState<ConsoleState>({
    stdout: '',
    stderr: '',
    input: ''
  });

  const appendStdout = (text: string) =>
    setConsoleState(prev => ({ ...prev, stdout: prev.stdout + text + '\n' }));
  const appendStderr = (text: string) =>
    setConsoleState(prev => ({ ...prev, stderr: prev.stderr + text + '\n' }));

  const handleSelectTool = (tool: Tool) => {
    setSelectedTool(tool);
  };

  const handleRun = async ({ target, args }: { target: string; args: string }) => {
    if (!selectedTool) return;

    setRunning(true);
    appendStdout(`> [${selectedTool.label}] target=${target} args=${args || '(none)'}`);

    try {
      switch (selectedTool.id) {
        case 'nmap_scan': {
          const data = await runNmapScan(target, args);
          setGraph(data);
          appendStdout(`Nmap scan complete. Nodes=${data.nodes.length} Links=${data.links.length}`);
          break;
        }
        default:
          appendStderr(
            `Tool "${selectedTool.label}" not yet wired. Implement API call on the Go side and hook it here.`
          );
      }
    } catch (err: any) {
      appendStderr(`Error: ${err.message || String(err)}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="app-root">
      <Navbar running={running} />
      <div className="app-main">
        <ToolPanel selectedToolId={selectedTool?.id ?? null} onSelectTool={handleSelectTool} />
        <div className="divider-vertical left" />
        <div className="center-column">
          <GraphCanvas graph={graph} />
          <div className="divider-horizontal" />
          <ConsolePanel
            state={consoleState}
            onInputChange={val =>
              setConsoleState(prev => ({
                ...prev,
                input: val
              }))
            }
          />
        </div>
        <div className="divider-vertical right" />
        <ArgsPanel selectedTool={selectedTool} onRun={handleRun} running={running} />
      </div>
    </div>
  );
};

export default App;