import React from 'react';

interface Props {
  running: boolean;
}

const Navbar: React.FC<Props> = ({ running }) => {
  return (
    <div className="navbar">
      <div className="navbar-title">Rustygo Operator</div>
      <div className="navbar-status">
        Status:{' '}
        <span className={running ? 'pill pill-running' : 'pill pill-idle'}>
          {running ? 'Running' : 'Idle'}
        </span>
      </div>
    </div>
  );
};

export default Navbar;