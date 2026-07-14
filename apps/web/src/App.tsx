import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import HostsPage from "./pages/HostsPage";
import ControlsPage from "./pages/ControlsPage";
import JobsPage from "./pages/JobsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/hosts" replace />} />
        <Route path="/hosts" element={<HostsPage />} />
        <Route path="/controls" element={<ControlsPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="*" element={<Navigate to="/hosts" replace />} />
      </Route>
    </Routes>
  );
}
