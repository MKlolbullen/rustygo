import React, { useEffect, useRef } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { GraphData } from '../types';

interface Props {
  graph: GraphData | null;
}

const GraphCanvas: React.FC<Props> = ({ graph }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': '#38bdf8',
              label: 'data(label)',
              'font-size': '10px',
              color: '#e5e7eb',
              'text-wrap': 'wrap',
              'text-max-width': 90,
              'border-width': 1,
              'border-color': '#0f172a'
            }
          },
          {
            selector: 'node[type = "host"]',
            style: {
              'background-color': '#22c55e'
            }
          },
          {
            selector: 'edge',
            style: {
              width: 1,
              'line-color': '#64748b',
              'target-arrow-color': '#64748b',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier'
            }
          }
        ]
      });
    }

    const cy = cyRef.current;

    if (!graph) {
      cy.elements().remove();
      return;
    }

    const elements = [
      ...graph.nodes.map(n => ({
        data: { id: n.id, label: n.label || n.id, type: n.type }
      })),
      ...graph.links.map((l, idx) => ({
        data: { id: `e${idx}`, source: l.source, target: l.target }
      }))
    ];

    cy.elements().remove();
    cy.add(elements as any);
    cy.layout({ name: 'cose', animate: true }).run();
    cy.fit(undefined, 40);
  }, [graph]);

  return <div className="graph-canvas" ref={containerRef} />;
};

export default GraphCanvas;