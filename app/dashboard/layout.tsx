import SideMenu from '../components/SideMenu';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="flex">
      <SideMenu />
      <main className="flex-1 p-6">
        {children}
      </main>
    </div>
  );
}