import React, { useState } from 'react';

export interface ConsoleState {
  stdout: string;
  stderr: string;
  input: string;
}

interface Props {
  state: ConsoleState;
  onInputChange?: (value: string) => void;
}

const ConsolePanel: React.FC<Props> = ({ state, onInputChange }) => {
  const [tab, setTab] = useState<'stdout' | 'stderr' | 'input'>('stdout');

  const currentContent =
    tab === 'stdout' ? state.stdout : tab === 'stderr' ? state.stderr : state.input;

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    if (onInputChange) onInputChange(e.target.value);
  };

  return (
    <div className="console-panel">
      <div className="console-tabs">
        <button
          className={'console-tab' + (tab === 'stdout' ? ' console-tab-active' : '')}
          onClick={() => setTab('stdout')}
        >
          stdout
        </button>
        <button
          className={'console-tab' + (tab === 'stderr' ? ' console-tab-active' : '')}
          onClick={() => setTab('stderr')}
        >
          stderr
        </button>
        <button
          className={'console-tab' + (tab === 'input' ? ' console-tab-active' : '')}
          onClick={() => setTab('input')}
        >
          input
        </button>
      </div>
      <div className="console-body">
        {tab === 'input' ? (
          <textarea
            className="console-textarea"
            value={currentContent}
            onChange={handleInputChange}
            placeholder="Type input for tools / agents here…"
          />
        ) : (
          <pre className="console-pre">{currentContent || '(empty)'}</pre>
        )}
      </div>
    </div>
  );
};

export default ConsolePanel;