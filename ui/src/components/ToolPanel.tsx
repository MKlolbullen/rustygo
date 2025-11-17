import React from 'react';
import { TOOL_CATEGORIES, TOOLS } from '../tools';
import { Tool } from '../types';

interface Props {
  selectedToolId: string | null;
  onSelectTool: (tool: Tool) => void;
}

const ToolPanel: React.FC<Props> = ({ selectedToolId, onSelectTool }) => {
  return (
    <div className="panel panel-left">
      <h3 className="panel-title">Tools</h3>
      <div className="panel-scroll">
        {TOOL_CATEGORIES.map(cat => {
          const tools = TOOLS.filter(t => t.category === cat.id).sort((a, b) =>
            a.label.localeCompare(b.label)
          );
          if (!tools.length) return null;
          return (
            <div key={cat.id} className="tool-category">
              <div className="tool-category-title">{cat.label}</div>
              <ul className="tool-list">
                {tools.map(t => (
                  <li
                    key={t.id}
                    className={
                      'tool-item' + (selectedToolId === t.id ? ' tool-item-selected' : '')
                    }
                    onClick={() => onSelectTool(t)}
                  >
                    <div className="tool-label">{t.label}</div>
                    {t.description && (
                      <div className="tool-desc">{t.description}</div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ToolPanel;