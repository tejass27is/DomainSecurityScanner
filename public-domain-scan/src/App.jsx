import { Routes, Route, Navigate } from 'react-router-dom';
import PublicScanPage from './pages/PublicScanPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<PublicScanPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
