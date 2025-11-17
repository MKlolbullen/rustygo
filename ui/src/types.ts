export interface GraphNode {
  id: string;
  type: string;
  label?: string;
}

export interface GraphLink {
  source: string;
  target: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export type ToolCategory =
  | 'recon'
  | 'auxiliary'
  | 'enumeration'
  | 'crawling'
  | 'fuzzing'
  | 'vulnerabilities'
  | 'privilege-escalation'
  | 'exploitation'
  | 'post-exploitation'
  | 'persistence'
  | 'scanning';

export interface Tool {
  id: string;
  label: string;
  category: ToolCategory;
  description?: string;
}