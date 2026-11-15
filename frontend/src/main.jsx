import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { AuthProvider, FlashProvider } from './context';
import './styles/app.css';
import './ripple';

createRoot(document.getElementById('root')).render(
    <BrowserRouter>
    <FlashProvider>
      <AuthProvider>
        <App />
      </AuthProvider>
    </FlashProvider>
  </BrowserRouter>
);
