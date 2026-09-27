import { NavLink, Route, Routes } from "react-router-dom";
import UploadPage from "./pages/UploadPage";
import HistoryPage from "./pages/HistoryPage";
import DetailPage from "./pages/DetailPage";

export default function App() {
  return (
    <div className="layout">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">⛨</span>
          <div>
            <h1>供应链核验工作台</h1>
            <p>DSSE 证据 · in-toto 声明 · OPA 信任策略</p>
          </div>
        </div>
        <nav>
          <NavLink to="/" end>
            上传核验
          </NavLink>
          <NavLink to="/history">历史记录</NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/verifications/:id" element={<DetailPage />} />
        </Routes>
      </main>
      <footer className="footer">
        安全约束:上传的产物仅用于 SHA-256 摘要计算,任何路径下都不会执行产物内容。
      </footer>
    </div>
  );
}
