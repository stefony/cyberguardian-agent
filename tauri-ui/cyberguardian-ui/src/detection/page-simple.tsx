export default function DetectionPage() {
  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Detection</h1>
        <p className="text-muted-foreground">Real-time threat detection</p>
      </div>

      <div className="bg-dark-surface p-6 rounded-lg border border-dark-border">
        <p className="text-center text-muted-foreground">Detection engine active</p>
      </div>
    </div>
  );
}