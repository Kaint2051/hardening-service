import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import HostsPage from "./pages/HostsPage";
import ControlsPage from "./pages/ControlsPage";
import JobsPage from "./pages/JobsPage";
import ComplianceWizardPage from "./pages/ComplianceWizardPage";
import RemediationQueuePage from "./pages/RemediationQueuePage";
import RiskOverviewPage from "./pages/RiskOverviewPage";
import SettingsPage from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        {/* "Kiểm tra & Khắc phục" là màn hình vận hành hằng ngày — mặc định
            vào thẳng đây thay vì /hosts, xem Layout.tsx. */}
        <Route index element={<Navigate to="/compliance" replace />} />
        <Route path="/compliance" element={<ComplianceWizardPage />} />
        <Route path="/remediation-queue" element={<RemediationQueuePage />} />
        <Route path="/risk-overview" element={<RiskOverviewPage />} />
        <Route path="/hosts" element={<HostsPage />} />
        <Route path="/controls" element={<ControlsPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/compliance" replace />} />
      </Route>
    </Routes>
  );
}
