import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthGate } from "./components/AuthGate";
import { Landing } from "./pages/Landing";
import { DashboardLayout } from "./layouts/DashboardLayout";
import { Overview } from "./pages/app/Overview";
import { Lab } from "./pages/app/Lab";
import { Assessments } from "./pages/app/Assessments";
import { AssessmentDetail } from "./pages/app/AssessmentDetail";
import { Targets } from "./pages/app/Targets";
import { Modules } from "./pages/app/Modules";
import { Findings } from "./pages/app/Findings";
import { FindingDetail } from "./pages/app/FindingDetail";
import { EvidenceExplorer } from "./pages/app/Evidence";
import { Reports } from "./pages/app/Reports";
import { Settings } from "./pages/app/Settings";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/app"
          element={
            <AuthGate>
              <DashboardLayout />
            </AuthGate>
          }
        >
          <Route index element={<Overview />} />
          <Route path="lab" element={<Lab />} />
          <Route path="assessments" element={<Assessments />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />
          <Route path="targets" element={<Targets />} />
          <Route path="modules" element={<Modules />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:id" element={<FindingDetail />} />
          <Route path="evidence" element={<EvidenceExplorer />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
